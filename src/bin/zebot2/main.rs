use std::error::Error;
use std::io;
use std::net::ToSocketAddrs;
use std::time::Duration;

use clap::Parser;
use irc2;
use tokio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_rustls::TlsStream;

use tracing::{info, warn, error, debug};

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Settings {
    /// Server to connect to
    #[clap(short, long, default_value = "irc.libera.chat:6697")]
    server: String,

    /// Nickname
    #[clap(short = 'n', long, default_value = "ZeBot-NG")]
    nickname: String,

    /// Real Name
    #[clap(short = 'r', long, default_value = "ZeBot the 2nd")]
    realname: String,

    /// Password File
    #[clap(short = 'P', long)]
    password_file: Option<String>,

    /// Channels to join
    #[clap(short, long)]
    channels: Vec<String>,

    /// Server ping timeout
    #[clap(short = 't', long, default_value_t = 5*60)]
    server_timeout: u64,
}

async fn connect(args: &Settings) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
    let addr = args.server.to_socket_addrs().expect("server address").next().ok_or("Could not create server address")?;
    Ok(TcpStream::connect(addr).await?)
}

#[cfg(feature = "native-tls")]
pub(crate) async fn connect_tls(args: &Settings) -> Result<tokio_native_tls::TlsStream<TcpStream>, Box<dyn Error + Send + Sync>> {
    let sock = connect(args).await?;
    let cx = tokio_native_tls::native_tls::TlsConnector::builder().build()?;
    let cx = tokio_native_tls::TlsConnector::from(cx);
    Ok(cx.connect(args.server.split(':').next().ok_or("invalid server name")?, sock).await?)
}

#[cfg(not(feature = "native-tls"))]
pub(crate) async fn connect_tls(args: &Settings) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn Error + Send + Sync>> {
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
    let sock = connect(args).await?;
    let domain = tokio_rustls::rustls::ServerName::try_from(args.server.split(':').next().ok_or("invalid server name")?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;
    Ok(connector.connect(domain, sock).await?)
}

#[derive(Debug)]
enum ServerCommand {
    Message(String, String),
    Join(String),
    Leave(String),
    Disconnect(String),
    Connect { server: String, nick: irc2::Nickname },
    Quit,
    Logon { nick: String, realname: String },
}

#[derive(Debug)]
enum ClientCommand {
    IRC(irc2::Message),
    ServerQuit(String),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut my_subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .with_thread_ids(false)
        .with_thread_names(false)
        .finish();
    tracing::subscriber::set_global_default(my_subscriber)
        .expect("setting tracing default failed");

    let args = Settings::parse();
    let (client_send, server_recv) = channel(16);
    let (server_send, client_recv) = channel(16);

    let srv = spawn(server(server_recv, server_send.clone(), args.clone()));
    let cmdl = spawn(cmdline(client_recv, client_send.clone(), args.clone()));

    tokio::join!(srv, cmdl);

    std::process::exit(0);

    Ok(())
}

async fn cmdline(mut recv: Receiver<ClientCommand>, mut send: Sender<ServerCommand>, args: Settings) ->  Result<(), Box<dyn Error + Send + Sync>> {
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut line = String::with_capacity(256);

    loop {
        tokio::select! {
            msg = recv.recv() => {
                if msg.is_none() {
                    continue;
                }
                let msg = msg.unwrap();
                match &msg {
                    ClientCommand::IRC(msg) => {
                        if msg.command == irc2::command::CommandCode::Notice &&
                            msg.params.len() == 2 && msg.params[1].contains("Checking Ident") &&
                            matches!(msg.prefix, Some(irc2::Prefix::Server(_))) {
                            send.send(ServerCommand::Logon {nick: args.nickname.clone(), realname: args.realname.clone()}).await?;

                            if let Some(pwfile) = &args.password_file {
                                match tokio::fs::File::open(&pwfile).await {
                                    Ok(mut f) => {
                                        let mut pw = String::new();
                                        f.read_to_string(&mut pw).await?;
                                        send.send(ServerCommand::Message("NickServ".to_string(), format!("identify {}", pw.trim()))).await?;
                                    }
                                    Err(e) => warn!("Could not open password file {}: {:?}", &pwfile, e),
                                }
                            }

                            // join initial channels
                            for c in args.channels.iter() {
                                send.send(ServerCommand::Join(c.clone())).await?;
                            }
                        }
                    }
                    ClientCommand::ServerQuit(reason) => {
                        info!("Server quit: {}", reason);
                        break;
                    }
                    _ => {

                    }
                }
            }

            n = stdin.read_line(&mut line) => {
                match n {
                    Err(e) => {
                        warn!("Error reading from stdin... quitting");
                        send.send(ServerCommand::Quit).await?;
                        return Ok(());
                    }
                    Ok(n) if n == 0 => {
                        warn!("Got EOF... quitting");
                        send.send(ServerCommand::Quit).await?;
                        continue;
                    }
                    Ok(_) => (),
                }

                let stripped = line.strip_suffix('\n').ok_or("stripped")?;
                dbg!(n, &stripped);
                line.clear();
            }
        }
    }

    Ok(())
}

async fn sock_send(sock: &mut tokio_rustls::client::TlsStream<TcpStream>, data: String) ->  Result<(), Box<dyn Error + Send + Sync>> {
    for part in data.split("\r\n").filter(|p| !p.is_empty()) {
        debug!("send: {}", part);
    }
    Ok(sock.write_all(data.as_bytes()).await?)
}

async fn server(mut recv: Receiver<ServerCommand>, mut send: Sender<ClientCommand>, args: Settings) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut sock = connect_tls(&args).await?;

    let mut buf = vec![0u8; 1 << 16];
    let mut rem = 0;
    let mut retries = 5;
    let mut logon = false;

    while retries > 0 {
        tokio::select! {
            msg = recv.recv() => {
                if msg.is_none() {
                    continue;
                }

                let msg = msg.unwrap();
                match msg {
                    ServerCommand::Quit => {
                        info!("Got quit message ...");
                        send.send(ClientCommand::ServerQuit("Received QUIT".to_string())).await?;
                        break;
                    }

                    ServerCommand::Message(dst, msg) => {
                        sock_send(&mut sock, format!("PRIVMSG {}: {}\r\n", dst, msg)).await?;
                    }

                    ServerCommand::Logon {nick, realname} => {
                        let msg = format!(
                            "USER {} none none :{}\r\nNICK :{}\r\n",
                            &nick, &realname, &nick,
                        );
                        sock_send(&mut sock, msg).await?;
                    }

                    ServerCommand::Join(chan) => {
                        sock_send(&mut sock, format!("JOIN :{}\r\n", chan)).await?;
                    }

                    _ => {

                    }
                }
            }

            n = tokio::time::timeout(Duration::from_secs(args.server_timeout), sock.read(&mut buf[rem ..])) => {
                let n = match n {
                    Err(e) => {
                        send.send(ClientCommand::ServerQuit("timeout".to_string())).await?;
                        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "timeout")));
                    }
                    Ok(n) => n?,
                };

                if n == 0 {
                    retries -= 1;
                    continue;
                }

                retries = 5;

                let data = &buf[..rem + n];
                let mut pos = 0;

                loop {
                    match irc2::parse(&data[pos..]) {
                        Ok((r, msg)) => {
                            use nom::Offset;
                            pos = data.offset(r);

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

                                    sock_send(&mut sock, resp).await?;
                                }
                                Quit => {

                                }
                                Error => {

                                }
                                _ => (),
                            }

                            send.send(ClientCommand::IRC(msg.clone())).await?;
                        }

                        // Input ended, no remaining bytes, just continue as normal
                        Err(e) if e.is_incomplete() => {
                            info!("Need to read more, irc2::parse: {:?}", e);
                            let l = data.len();
                            dbg!(l, pos);
                            buf.copy_within(pos..pos+l, 0);
                            rem = 0;
                            break;
                        }

                        Err(e) if ! (&data[pos..]).is_empty() => {
                            error!("Error from parser: {:?}", e);
                            rem = pos;
                            break;
                        }

                        _ => {
                            rem = 0;
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
