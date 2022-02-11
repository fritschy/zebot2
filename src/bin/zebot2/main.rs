use std::error::Error;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use clap::Parser;
use irc2;
use tokio;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver};

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Settings {
    /// Server to connect to
    #[clap(short, long, default_value = "irc.libera.chat:6697")]
    server: String,

    /// Nickname
    #[clap(short = 'n', long, default_value = "2eBot")]
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
enum ZebotMessage {
    Send(String),
    Quit,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Settings::parse();
    let (send, recv) = channel(16);

    let srv = spawn(server(recv, args.clone()));
    tokio::time::sleep(Duration::from_secs(5)).await;
    let quit = send.send(ZebotMessage::Quit);

    tokio::join!(srv, quit);

    Ok(())
}

async fn server(mut chan: Receiver<ZebotMessage>, args: Settings) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut sock = connect_tls(&args).await?;

    dbg!(&sock);
    dbg!(&args);

    let mut buf = vec![0u8; 1 << 16];
    let mut rem = 0;
    let mut retries = 5;

    while retries > 0 {
        tokio::select! {
            msg = chan.recv() => {
                match msg {
                    Some(ZebotMessage::Quit) => {
                        println!("Got quit message ...");
                        break;
                    }

                    _ => {

                    }
                }
            }

            n = sock.read(&mut buf[rem ..]) => {
                let n = n?;
                if n == 0 {
                    retries -= 1;
                    continue;
                }

                retries = 5;

                let data = &buf[..rem + n];
                dbg!(String::from_utf8_lossy(&data[..]));
            }
        }
    }

    println!("Server quitting...");

    Ok(())
}
