use tokio;
use clap::Parser;

use irc2;
use tokio::net::TcpStream;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Settings {
    // Server to connect to
    #[clap(short, long, default_value = "localhost")]
    server: String,

    // Server port
    #[clap(short, long, default_value_t = 6667)]
    port: u16,

    // force SSL
}

#[tokio::main]
async fn main() {
    let args = Settings::parse();

    let stream = TcpStream::connect(format!("{}:{}", args.server, args.port)).await.expect("connect");

    dbg!(args);
}
