use std::error::Error;
use std::time::Instant;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tracing::{info, warn};

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

    async fn handle_zebot_command(&self, dst: &str, cmd: &str, args: &[&str]) -> Result<(), Box<dyn Error + Send + Sync>> {
        match cmd {
            "!up" | "!uptime" => {
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

                r += &format!("{:02}:{:02}:{:02}", h, m, u);

                self.message(dst, &format!("{} uptime", r)).await?;
            }

            _ => (),
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
