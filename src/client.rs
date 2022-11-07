use crate::control::ControlCommand;
use crate::readerbuf::ReaderBuf;
use crate::Settings;
use std::error::Error;
use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, error, info};

#[derive(Debug)]
pub enum ClientCommand {
    Message(String, String),
    Join(String),
    Quit,
    Logon { nick: String, realname: String },
    RawMessage(String),
}

async fn connect(settings: &Settings) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
    let addr = settings
        .server
        .to_socket_addrs()?
        .next()
        .ok_or("Could not create server address")?;
    let sock = TcpStream::connect(addr).await?;
    sock.set_nodelay(true)?;
    Ok(sock)
}

async fn connect_tls(
    settings: &Settings,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn Error + Send + Sync>> {
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        tokio_rustls::rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let sock = connect(settings).await?;
    let domain = tokio_rustls::rustls::ServerName::try_from(
        settings
            .server
            .split(':')
            .next()
            .ok_or("invalid server name")?,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;
    Ok(connector.connect(domain, sock).await?)
}

async fn sock_send<T: AsyncWriteExt + Unpin>(
    sock: &mut T,
    rate_limit: &mut leaky_bucket_lite::LeakyBucket,
    data: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    rate_limit.acquire_one().await;
    for part in data.split("\r\n").filter(|p| !p.is_empty()) {
        debug!("send: {}", part);
    }
    sock.write_all(data.as_bytes()).await?;

    // Should we need to flush here immediately?
    sock.flush().await?;

    Ok(())
}

pub async fn task(
    mut cmd: Receiver<ClientCommand>,
    ctrl: Sender<ControlCommand>,
    settings: Arc<Settings>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut sock = connect_tls(&settings).await?;
    let mut bufs = ReaderBuf::new();

    let mut retries = 5;

    let mut send_rate_limit = leaky_bucket_lite::LeakyBucket::builder()
        .max(9)
        .refill_amount(1)
        .refill_interval(Duration::from_millis(1500))
        .tokens(7)
        .build();

    let mut parse_retry = false;

    while retries > 0 {
        tokio::select! {
            msg = cmd.recv() => {
                if msg.is_none() {
                    continue;
                }

                let msg = msg.unwrap();
                match msg {
                    ClientCommand::Quit => {
                        info!("Got quit message ...");
                        ctrl.send(ControlCommand::ServerQuit("Received QUIT".to_string())).await?;
                        sock_send(&mut sock, &mut send_rate_limit, "QUIT :Need to restart the distributed real-time Java cluster VM\r\n").await?;
                        break;
                    }

                    ClientCommand::Message(dst, msg) => {
                        sock_send(&mut sock, &mut send_rate_limit, &format!("PRIVMSG {} :{}\r\n", dst, msg)).await?;
                    }

                    ClientCommand::RawMessage(msg) => {
                        sock_send(&mut sock, &mut send_rate_limit, &msg).await?;
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
                }
            }

            n = tokio::time::timeout(Duration::from_secs(settings.server_timeout), bufs.read_from(&mut sock)) => {
                let n = match n {
                    Err(_) => {
                        ctrl.send(ControlCommand::ServerQuit("timeout".to_string())).await?;
                        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "timeout")));
                    }
                    Ok(n) => n?,
                };

                if n == 0 {
                    retries -= 1;
                    continue;
                }

                retries = 5;

                let mut i = &bufs.buf[..n];

                while !i.is_empty() {
                    match irc2::parse(i) {
                        Ok((r, msg)) => {
                            parse_retry = false;
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
                                Error => {
                                    error!("Error from server: {msg}");
                                    ctrl.send(ControlCommand::ServerQuit("Received ERROR from server".to_string())).await?;
                                    return Err(Box::new(io::Error::new(io::ErrorKind::Other, "IRC Error from Server")));
                                }
                                _ => (),
                            }

                            // Forward IRC message to control for handling
                            ctrl.send(ControlCommand::Irc(msg.clone())).await?;
                        }

                        Err(e) if parse_retry => {
                            // This one is fatal, we ran into parse errors a couple of times...
                            error!("Encountered an error from parser: {e:?}");
                            ctrl.send(ControlCommand::ServerQuit("Parse error".to_string())).await?;
                            return Err(Box::new(io::Error::new(io::ErrorKind::Other, "IRC parse error")));
                        }

                        // Input ended, no remaining bytes, just continue as normal
                        Err(_) => {
                            // We do not correctly have Incomplete-info from parser, so we need to
                            // treat every error as possibly "Incomplete". So at least, retry a couple
                            // of times...
                            parse_retry = true;
                            error!("Incomplete parse, retry");
                            bufs.push_to_last(i);
                            break;
                        }
                    }
                }
            }
        }
    }

    info!("Server quitting...");

    Ok(())
}
