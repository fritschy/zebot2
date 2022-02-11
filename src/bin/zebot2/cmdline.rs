use std::error::Error;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Instant;
use nom::AsBytes;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::Settings;
use crate::server::{ServerCommand};

#[derive(Debug)]
pub(crate) enum ClientCommand {
    Irc(irc2::Message),
    ServerQuit(String),
}

#[derive(Debug)]
struct Client<'a> {
    startup: Instant,
    settings: &'a Settings,
    send: Sender<ServerCommand>,
}

impl<'a> Client<'a> {
    async fn message(&self, dst: &str, msg: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send.send(ServerCommand::Message(dst.to_string(), msg.to_string())).await?;
        Ok(())
    }

    async fn handle_command_uptime(&self, dst: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut u = self.startup.elapsed().as_secs();
        let mut r = String::new();

        if u >= 3600 * 24 * 365 {
            let y = u / (3600 * 24 * 365);
            r += &format!("{}y ", y);
            u -= y * 3600 * 24 * 365;
        }

        if u >= 3600 * 24 {
            let d = u / (3600 * 24);
            r += &format!("{}d ", d);
            u -= d * 3600 * 24;
        }

        let h = u / 3600;
        u -= h * 3600;

        let m = u / 60;
        u -= m * 60;

        r += &format!("{:02}:{:02}:{:02} uptime", h, m, u);

        self.message(dst, &r).await?;

        Ok(())
    }

    async fn handle_zebot_command(&self, dst: &str, cmd: &str, args: &[&str]) -> Result<(), Box<dyn Error + Send + Sync>> {
        match cmd {
            "!up" | "!uptime" => self.handle_command_uptime(dst).await?,
            _ => warn!("Unknown command \"{}\"", cmd),
        }
        Ok(())
    }

    async fn youtube_title(&self, dst: &str, text: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let yt_re = regex::Regex::new(r"https?://((www.)?youtube\.com/watch|youtu.be/)").unwrap();
        for url in text
            .split_ascii_whitespace()
            .filter(|&x| x.starts_with("https://") || x.starts_with("http://")) {
            if yt_re.is_match(url) {
                if let Ok(output) = Command::new("python3")
                    .current_dir("youtube-dl")
                    .args(&[
                        "-m", "youtube_dl", "--quiet", "--get-title", "--socket-timeout", "5", url,
                    ])
                    .output().await {
                    let err = String::from_utf8_lossy(output.stderr.as_ref());
                    if !err.is_empty() {
                        error!("Got error from youtube-dl: {}", err);
                        self.message(dst, &format!("Got an error for URL {}, is this a valid video URL?", &url)).await?;
                    } else {
                        let title = String::from_utf8_lossy(output.stdout.as_ref());
                        if !title.is_empty() {
                            self.message(dst, &format!("{} has title '{}'", &url, title.trim())).await?;
                        }
                    }
                }
            } else {
                // xpath: "//html/body/*[local-name() = \"h1\"]/text()"

                // let r = reqwest::get(url).await?;
                // let b = r.text().await?;

                // let mut in_h1 = false;
                // for token in html5gum::Tokenizer::new(&b).infallible() {
                //     match token {
                //         html5gum::Token::StartTag(tag) if tag.name.as_slice().to_ascii_lowercase() == b"h1" => {
                //             in_h1 = true;
                //         }
                //         html5gum::Token::String(s) if in_h1 => {
                //             dbg!(String::from_utf8_lossy(s.as_slice()));
                //         }
                //         html5gum::Token::EndTag(tag) if tag.name.as_slice().to_ascii_lowercase() == b"h1" => {
                //             in_h1 = false;
                //             break;
                //         }
                //         _ => (),
                //     }
                // }

                // // xml parser; doesn't pars e.g. https://heise.de/
                // let mut er = xml::EventReader::new(BufReader::new(b.as_bytes()));
                // let mut in_h1 = false;
                // for e in er {
                //     dbg!(&e);
                //     match &e {
                //         Ok(xml::reader::XmlEvent::StartElement { name, .. }) if name.to_string() == "h1" => {
                //             in_h1 = true;
                //         }
                //         Ok(xml::reader::XmlEvent::Characters(s)) if in_h1 => {
                //             info!("Got string from h1: '{}'", s);
                //         }
                //         Ok(xml::reader::XmlEvent::EndElement { name, .. }) if name.to_string() == "h1" => {
                //             in_h1 = false;
                //             break;
                //         }
                //         _ => (),
                //     }
                // }


            //    // I can't figure out how to not make this one crash with tokio...
            //    use select::document::Document;
            //    use select::predicate::{Class, Name};
            //    let r = reqwest::get(url).await;
            //    if let Ok(r) = r {
            //        if let Ok(s) = r.text().await {
            //            let d = Mutex::new(Document::from(s.as_str()));
            //            if let Some(h1) = d.lock().await.find(Name("h1")).next() {
            //                let title = h1.text();
            //                self.message(dst, &format!("{} has title '{}'", &url, title.trim())).await?;
            //            }
            //        }
            //    }
            }
        }
        Ok(())
    }

    async fn handle_privmsg(&self, msg: &irc2::Message) -> Result<(), Box<dyn Error + Send + Sync>> {
        let cmd = &msg.command;

        if cmd != &irc2::command::CommandCode::PrivMsg {
            return Ok(());
        }

        let args = &msg.params;
        let argc = args.len();
        let dst = msg.get_reponse_destination(&self.settings.channels);

        if argc < 2 || args[1].is_empty() {
            warn!("Improper PRIVMSG: {}", msg);
            return Ok(());
        }

        let text = &args[1];

        if text.starts_with('!') && text.len() > 1 && text.as_bytes()[1].is_ascii_alphanumeric() {
            let textv = text.split_ascii_whitespace().collect::<Vec<_>>();
            self.handle_zebot_command(&dst, text.as_str(), &textv[1..]).await?;
            return Ok(());
        }

        self.youtube_title(&dst, text.as_str()).await?;

        info!("{}", msg);

        Ok(())
    }

    async fn logon(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send.send(ServerCommand::Logon {nick: self.settings.nickname.clone(), realname: self.settings.realname.clone()}).await?;

        if let Some(pwfile) = &self.settings.password_file {
            match tokio::fs::File::open(&pwfile).await {
                Ok(mut f) => {
                    let mut pw = String::new();
                    f.read_to_string(&mut pw).await?;
                    self.send.send(ServerCommand::Message("NickServ".to_string(), format!("identify {}", pw.trim()))).await?;
                }
                Err(e) => warn!("Could not open password file {}: {:?}", &pwfile, e),
            }
        }

        // join initial channels
        for c in self.settings.channels.iter() {
            self.send.send(ServerCommand::Join(c.clone())).await?;
        }

        Ok(())
    }

    async fn handle_irc_command(&self, msg: &irc2::Message) -> Result<(), Box<dyn Error + Send + Sync>> {
        use irc2::command::CommandCode;

        let args = &msg.params;
        let argc = args.len();
        let cmd = &msg.command;
        let pfx = &msg.prefix;

        match cmd {
            CommandCode::Notice if argc == 2
                && args[1].contains("Checking Ident")
                && matches!(pfx, Some(irc2::Prefix::Server(_))) => self.logon().await?,

            CommandCode::PrivMsg => self.handle_privmsg(msg).await?,

            _ => {
                warn!("Missing handler: {}", msg);
            }
        }

        Ok(())
    }
}

pub(crate) async fn cmdline(mut recv: Receiver<ClientCommand>, send: Sender<ServerCommand>, settings: Settings) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut line = String::with_capacity(1024);

    let client = Client {startup: Instant::now(), settings: &settings, send: send.clone()};

    loop {
        tokio::select! {
            msg = recv.recv() => {
                if let Some(msg) = &msg {
                    match msg {
                        ClientCommand::Irc(msg) => client.handle_irc_command(msg).await?,

                        ClientCommand::ServerQuit(reason) => {
                            recv.close();
                            info!("Server quit: {}", reason);
                            break;
                        }
                    }
                }
            }

            n = stdin.read_line(&mut line) => {
                match n {
                    Err(_) => {
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

                let stripped = line.strip_suffix('\n').unwrap_or(&line);
                send.send(ServerCommand::Message(settings.channels[0].clone(), stripped.to_string())).await?;
                line.clear();
            }
        }
    }

    Ok(())
}
