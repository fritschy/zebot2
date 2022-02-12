use std::error::Error;

use clap::Parser;
use tokio::spawn;
use tokio::sync::mpsc::{channel};

mod control;
mod client;

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

    /// Extra options e.g. -x youtube_dl=$PWD/youtube-dl
    #[clap(short = 'x', long = "extra")]
    extra_opts: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let my_subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .with_thread_ids(false)
        .with_thread_names(false)
        .finish();
    tracing::subscriber::set_global_default(my_subscriber)
        .expect("setting tracing default failed");

    let args = Settings::parse();
    let (client_send, server_recv) = channel(16);
    let (server_send, client_recv) = channel(16);

    let cl = spawn(client::task(server_recv, server_send.clone(), args.clone()));
    let ctrl = spawn(control::task(client_recv, client_send.clone(), args.clone()));

    let result = tokio::join!(cl, ctrl);
    result.0??;
    result.1??;

    std::process::exit(0);
}
