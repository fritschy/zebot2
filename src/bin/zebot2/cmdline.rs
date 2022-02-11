use std::error::Error;
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

async fn handle_privmsg(msg: &irc2::Message, send: Sender<ServerCommand>, args: &Settings) -> Result<(), Box<dyn Error + Send + Sync>> {
    Ok(())
}

async fn handle_irc_command(msg: &irc2::Message, send: Sender<ServerCommand>, args: &Settings) -> Result<(), Box<dyn Error + Send + Sync>> {
    use irc2::command::CommandCode;

    match &msg.command {
        Notice if msg.params.len() == 2
            && msg.params[1].contains("Checking Ident")
            && matches!(msg.prefix, Some(irc2::Prefix::Server(_))) => {

            // Logon
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

        _ => {
            warn!("Unimplemented command handler: {:?}", &msg.command);
        }
    }

    Ok(())
}

pub(crate) async fn cmdline(mut recv: Receiver<ClientCommand>, send: Sender<ServerCommand>, args: Settings) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut line = String::with_capacity(1024);

    loop {
        tokio::select! {
            msg = recv.recv() => {
                if msg.is_none() {
                    continue;
                }
                let msg = msg.unwrap();
                match &msg {
                    ClientCommand::Irc(msg) => handle_irc_command(&msg, send.clone(), &args).await?,

                    ClientCommand::ServerQuit(reason) => {
                        recv.close();
                        info!("Server quit: {}", reason);
                        break;
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

                let stripped = line.strip_suffix('\n').ok_or("stripped")?;
                send.send(ServerCommand::Message(args.channels[0].clone(), stripped.to_string())).await?;
                line.clear();
            }
        }
    }

    Ok(())
}
