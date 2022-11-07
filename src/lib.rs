pub mod client;
pub mod control;
pub mod readerbuf;
pub mod util;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Settings {
    /// Server to connect to
    #[clap(short, long, default_value = "irc.libera.chat:6697")]
    pub server: String,

    /// Nickname
    #[clap(short = 'n', long, default_value = "ZeBot-NG")]
    pub nickname: String,

    /// Real Name
    #[clap(short = 'r', long, default_value = "ZeBot the 2nd")]
    pub realname: String,

    /// Password File
    #[clap(short = 'P', long)]
    pub password_file: Option<String>,

    /// Channels to join
    #[clap(short, long="channel", parse(try_from_str=validate_channel))]
    pub channels: Vec<String>,

    /// Server ping timeout
    #[clap(short = 't', long, default_value_t = 3*60)]
    pub server_timeout: u64,

    /// Extra options e.g. -x youtube_dl=$PWD/youtube-dl
    #[clap(short = 'x', long = "extra")]
    pub extra_opts: Vec<String>,

    /// Restart internally on error
    #[clap(short = 'R', long, parse(from_flag))]
    pub restart: bool,

    /// Do not read from stdin, use e.g. when starting as a daemon
    #[clap(short = 'N', long, parse(from_flag))]
    pub no_stdin: bool,

    #[clap(long = "tokio-console", parse(from_flag))]
    pub tokio_console: bool,
}

fn validate_channel(arg: &str) -> Result<String, String> {
    if arg.chars().any(|c: char| ", \t".contains(c)) {
        Err(format!("Invalid channel name: '{arg}'"))
    } else {
        Ok(arg.to_string())
    }
}

impl Settings {
    fn get_extra(&self, key: &str) -> Option<&str> {
        self.extra_opts
            .iter()
            .filter_map(|e| e.strip_prefix(key).and_then(|x| x.strip_prefix('=')))
            .next()
    }
}
