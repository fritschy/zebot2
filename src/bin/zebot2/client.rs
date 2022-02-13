use std::error::Error;
use std::io;
use std::net::{ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};
use crate::control::{ControlCommand};
use tracing::{info, error, debug};
use crate::Settings;

#[derive(Debug)]
pub(crate) enum ClientCommand {
    Message(String, String),
    Join(String),
    Leave(String),
    Quit,
    Logon { nick: String, realname: String },
}

async fn connect(settings: &Settings) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
    let addr = settings.server.to_socket_addrs().expect("server address").next().ok_or("Could not create server address")?;
    Ok(TcpStream::connect(addr).await?)
}

async fn connect_tls(settings: &Settings) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn Error + Send + Sync>> {
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .0
            .iter()
            .map(|ta| {
                tokio_rustls::rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            })
    );
    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let sock = connect(settings).await?;
    let domain = tokio_rustls::rustls::ServerName::try_from(settings.server.split(':').next().ok_or("invalid server name")?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;
    Ok(connector.connect(domain, sock).await?)
}

async fn sock_send<T: AsyncWriteExt + Unpin>(sock: &mut T, rate_limit: &mut leaky_bucket_lite::LeakyBucket, data: &str) ->  Result<(), Box<dyn Error + Send + Sync>> {
    rate_limit.acquire(data.len() as u32).await;
    for part in data.split("\r\n").filter(|p| !p.is_empty()) {
        debug!("send: {}", part);
    }
    Ok(sock.write_all(data.as_bytes()).await?)
}

pub(crate) async fn task(mut recv: Receiver<ClientCommand>, send: Sender<ControlCommand>, settings: Arc<Settings>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut sock = connect_tls(&settings).await?;

    let mut buf = vec![0u8; 1 << 16];
    let mut off = 0;
    let mut retries = 5;

    let mut send_rate_limit = leaky_bucket_lite::LeakyBucket::builder()
        .max(256)
        .refill_amount(16)
        .refill_interval(Duration::from_millis(333))
        .tokens(256)
        .build();

    while retries > 0 {
        tokio::select! {
            msg = recv.recv() => {
                if msg.is_none() {
                    continue;
                }

                let msg = msg.unwrap();
                match msg {
                    ClientCommand::Quit => {
                        info!("Got quit message ...");
                        send.send(ControlCommand::ServerQuit("Received QUIT".to_string())).await?;
                        sock_send(&mut sock, &mut send_rate_limit, "QUIT :Need to restart the distributed real-time Java cluster VM\r\n").await?;
                        sock.flush().await?;
                        break;
                    }

                    ClientCommand::Message(dst, msg) => {
                        sock_send(&mut sock, &mut send_rate_limit, &format!("PRIVMSG {} :{}\r\n", dst, msg)).await?;
                    }

                    ClientCommand::Logon {nick, realname} => {
                        let msg = format!(
                            "USER {} none none :{}\r\nNICK :{}\r\n",
                            &nick, &realname, &nick,
                        );
                        sock_send(&mut sock, &mut send_rate_limit, &msg).await?;
                    }

                    ClientCommand::Join(chan) => {
                        sock_send(&mut sock, &mut send_rate_limit, &format!("JOIN :{}\r\n", chan)).await?;
                    }

                    ClientCommand::Leave(chan) => {
                        sock_send(&mut sock, &mut send_rate_limit, &format!("PART :{}\r\n", chan)).await?;
                    }
                }
            }

            n = tokio::time::timeout(Duration::from_secs(settings.server_timeout), sock.read(&mut buf[off ..])) => {
                let n = match n {
                    Err(_) => {
                        send.send(ControlCommand::ServerQuit("timeout".to_string())).await?;
                        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "timeout")));
                    }
                    Ok(n) => n?,
                };

                if n == 0 {
                    retries -= 1;
                    continue;
                }

                retries = 5;

                let mut i = &buf[..off + n];
                let pos = 0;

                while !i.is_empty() && i != b"\r\n" {
                    match irc2::parse(i) {
                        Ok((r, msg)) => {
                            i = r;

                            use irc2::command::CommandCode::*;
                            match msg.command {
                                Ping => {
                                    let dst = if let Some(prefix) = &msg.prefix {
                                        prefix.to_string()
                                    } else if !msg.params.is_empty() {
                                        msg.params[0].clone()
                                    } else {
                                        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Don't know how to respond to PING w/o params or prefix!")));
                                    };

                                    let resp = format!("PONG {} :{}\r\n", dst, dst);

                                    sock_send(&mut sock, &mut send_rate_limit, &resp).await?;
                                }
                                Quit => {

                                }
                                Error => {

                                }
                                _ => (),
                            }

                            send.send(ControlCommand::Irc(msg.clone())).await?;
                        }

                        // Input ended, no remaining bytes, just continue as normal
                        Err(e) if e.is_incomplete() => {
                            use nom::Offset;
                            info!("Need to read more, irc2::parse: {:?}", e);
                            let l = i.len();
                            let pos = buf.as_slice().offset(i);
                            dbg!(l, pos);
                            buf.copy_within(pos..pos+l, 0);
                            off = pos + l;
                            break;
                        }

                        Err(e) => {
                            error!("Error from parser: {:?}", e);
                            let l = i.len();
                            off = pos + l;
                            buf.copy_within(pos..pos+l, 0);
                            break;
                        }

                        _ => {
                            off = 0;
                            break;
                        }
                    }
                }
            }
        }

        sock.flush().await?;
    }

    info!("Server quitting...");

    Ok(())
}
