use std::net::{SocketAddr, ToSocketAddrs};
use std::error::Error;
use std::io;
use tokio;
use clap::Parser;

use irc2;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Settings {
    // Server to connect to
    #[clap(short, long, default_value = "irc.libera.chat")]
    server: String,

    // Server port
    #[clap(short, long, default_value_t = 6697)]
    port: u16,
}

fn resolve_addr(sp: (&str, u16)) -> Result<SocketAddr, Box<dyn Error + Send + Sync>> {
    Ok(sp.to_socket_addrs()?
        .next()
        .ok_or("Failed to resolve server name")?)
}

async fn connect(args: &Settings) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
    let addr = resolve_addr((args.server.as_str(), args.port))?;
    Ok(TcpStream::connect(addr).await?)
}

#[cfg(feature="native-tls")]
pub(crate) async fn connect_tls(args: &Settings) -> Result<tokio_native_tls::TlsStream<TcpStream>, Box<dyn Error + Send + Sync>> {
    let sock = connect(args).await?;
    let cx = tokio_native_tls::native_tls::TlsConnector::builder().build()?;
    let cx = tokio_native_tls::TlsConnector::from(cx);
    Ok(cx.connect("irc.libera.chat", sock).await?)
}

#[cfg(not(feature="native-tls"))]
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
    let domain = tokio_rustls::rustls::ServerName::try_from(args.server.as_str())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;
    Ok(connector.connect(domain, sock).await?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Settings::parse();

    let mut sock = connect_tls(&args).await?;

    let mut data = vec![0u8; 1<<16];
    let n = sock.read(&mut data).await?;
    let mut data = &mut data[..n];

    dbg!(&sock);
    dbg!(String::from_utf8_lossy(&data[..]));

    Ok(())
}
