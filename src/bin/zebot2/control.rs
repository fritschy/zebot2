use chrono::Local;
use irc2::command::CommandCode;
use irc2::{Message, Prefix};
use rand::prelude::*;
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use textwrap::word_splitters::NoHyphenation;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, info, warn};
use url::Url;

use crate::client::ClientCommand;
use crate::util::{greet, is_json_flag_set, nag_user, parse_substitution, text_box, zebot_version};
use crate::Settings;

async fn url_saver(
    msg: &irc2::Message,
    settings: Arc<Settings>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut filename = settings.get_extra("url_store").unwrap_or("").to_string();

    if filename.is_empty() {
        filename = "urls.txt".to_string();
    }

    let mut f = tokio::fs::OpenOptions::new()
        .truncate(false)
        .create(true)
        .write(true)
        .read(false)
        .append(true)
        .open(&filename)
        .await?;

    for word in msg.params[1].split_ascii_whitespace() {
        if let Ok(url) = Url::parse(word) {
            let nick = msg.get_nick();
            let chan = msg.get_reponse_destination(&settings.channels);
            info!("Got an url from {} {}: {}", &chan, &nick, url);
            let line = format!(
                "{}\t{}\t{}\t{}\n",
                Local::now().to_rfc3339(),
                chan,
                nick,
                url
            );
            f.write_all(line.as_bytes()).await?;
        }
    }

    Ok(())
}

async fn callout(
    msg: irc2::Message,
    settings: Arc<Settings>,
    send: Sender<ControlCommand>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if msg.params.len() < 2 || !msg.params[1].starts_with('!') {
        return Ok(());
    }

    let command = msg.params[1][1..]
        .split_ascii_whitespace()
        .next()
        .unwrap_or_default();
    if !command
        .chars()
        .all(|x| x.is_ascii_alphanumeric() || x == '-' || x == '_')
    {
        return Ok(());
    }

    let command = command.to_lowercase();

    let path = format!("./handlers/{}", command);

    if !Path::new(&path).exists() {
        return Ok(());
    }

    let nick = msg.get_nick();
    let mut args = msg.params.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    args.insert(0, nick); // this sucks

    // Handler args look like this:
    // $srcnick $src(chan,query) "!command[ ...args]"

    // json from handler
    // { "lines": [ ... ],
    //   "dst": "nick" | "channel",   # optional
    //   "box": "0"|"1"|true|false,   # optional
    //   "wrap": "0"|"1"              # optional
    //   "wrap_single_lines": "0"|"1" # optional
    //   "title": "string"            # optional
    //   "link": "string"             # optional
    // }

    dbg!(&args);

    spawn(async move {
        async fn wrapper(
            msg: Message,
            command: String,
            path: String,
            args: Vec<String>,
            settings: Arc<Settings>,
            send: Sender<ControlCommand>,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            let s = Instant::now();
            let cmd = Command::new("/usr/bin/timeout")
                .arg("30s")
                .arg(path)
                .args(&args)
                .output()
                .await;
            let s = s.elapsed();

            info!("Handler {} completed in {:?}", command, s);

            match cmd {
                Ok(p) => {
                    if !p.status.success() {
                        let dst = msg.get_reponse_destination(&settings.channels);
                        error!("Handler failed with code {}", p.status.code().unwrap());
                        dbg!(&p);
                        send.send(ControlCommand::TaskMessage(
                            dst,
                            "Somehow, that did not work...".to_string(),
                        ))
                        .await?;
                        return Ok(());
                    }

                    if let Ok(response) = String::from_utf8(p.stdout) {
                        dbg!(&response);
                        match json::parse(&response) {
                            Ok(response) => {
                                let dst = if response.contains("dst") {
                                    response["dst"].to_string()
                                } else {
                                    msg.get_reponse_destination(&settings.channels)
                                };

                                if response.contains("error") {
                                    dbg!(&response);
                                    send.send(ControlCommand::TaskMessage(
                                        dst,
                                        "Somehow, that did not work...".to_string(),
                                    ))
                                    .await?;
                                    return Ok(());
                                } else if !is_json_flag_set(&response["box"]) {
                                    for l in response["lines"].members() {
                                        send.send(ControlCommand::TaskMessage(
                                            dst.clone(),
                                            l.to_string(),
                                        ))
                                        .await?;
                                    }
                                } else {
                                    let lines = response["lines"]
                                        .members()
                                        .map(|x| x.to_string())
                                        .collect::<Vec<_>>();
                                    let lines = if is_json_flag_set(&response["wrap"])
                                        && lines.iter().map(|x| x.len()).any(|l| l > 80)
                                    {
                                        let nlines = lines.len();

                                        let s = if lines[nlines - 1].starts_with("    ") {
                                            let (lines, last) = lines.split_at(nlines - 1);

                                            let s = lines.concat();
                                            let s = textwrap::fill(&s, 80);

                                            let s = s + "\n";
                                            s + last[0].as_str()
                                        } else {
                                            let s = lines.concat();
                                            textwrap::fill(&s, 80)
                                        };

                                        s.split(|f| f == '\n')
                                            .map(|x| x.to_string())
                                            .collect::<Vec<_>>()
                                    } else if is_json_flag_set(&response["wrap_single_lines"]) {
                                        let mut new_lines = Vec::with_capacity(lines.len());
                                        let opt = textwrap::Options::new(80)
                                            .word_splitter(NoHyphenation)
                                            .subsequent_indent("  ");
                                        for l in lines {
                                            new_lines.extend(
                                                textwrap::wrap(&l, &opt)
                                                    .iter()
                                                    .map(|x| x.to_string()),
                                            );
                                        }
                                        new_lines
                                    } else {
                                        lines
                                    };

                                    // append link if provided
                                    let lines = if let Some(s) = response["link"].as_str() {
                                        let mut lines = lines;
                                        lines.push(format!("    -- {}", s));
                                        lines
                                    } else {
                                        lines
                                    };

                                    for i in text_box(lines.iter(), response["title"].as_str()) {
                                        send.send(ControlCommand::TaskMessage(dst.clone(), i))
                                            .await?;
                                    }
                                }
                            }

                            Err(e) => {
                                // Perhaps have this as a fallback for non-json handlers? What could possibly go wrong!
                                error!(
                                    "Could not parse json from handler {}: {}",
                                    command, response
                                );
                                error!("Error: {:?}", e);
                            }
                        }
                    } else {
                        error!("Could not from_utf8 for handler {}", command);
                    }
                }

                Err(e) => {
                    error!("Could not execute handler: {:?}", e);
                    return Ok(());
                }
            }

            Ok(())
        }

        if let Err(e) = wrapper(msg, command, path, args, settings, send).await {
            error!("Callout errored: {e:?}");
        }
    });

    Ok(())
}

async fn youtube_title(
    dst: String,
    text: String,
    send: Sender<ControlCommand>,
    settings: Arc<Settings>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let yt_re = regex::Regex::new(r"https?://((www.)?youtube\.com/watch|youtu.be/)").unwrap();
    for url in text
        .split_ascii_whitespace()
        .filter(|&x| x.starts_with("https://") || x.starts_with("http://"))
    {
        if yt_re.is_match(url) {
            let mut cmd_builder = Command::new("python3");
            if let Some(youtube_dl_dir) = settings.get_extra("youtube_dl") {
                cmd_builder.current_dir(youtube_dl_dir);
            }

            if let Ok(output) = cmd_builder
                .args(&[
                    "-m",
                    "yt_dlp",
                    "--quiet",
                    "--get-title",
                    "--socket-timeout",
                    "15",
                    url,
                ])
                .output()
                .await
            {
                let err = String::from_utf8_lossy(output.stderr.as_ref());
                if !err.is_empty() {
                    error!("Got error from youtube-dl: {}", err);
                    send.send(ControlCommand::TaskMessage(
                        dst.to_string(),
                        format!("Got an error for URL {}, is this a valid video URL?", &url),
                    ))
                    .await?;
                } else {
                    let title = String::from_utf8_lossy(output.stdout.as_ref());
                    if !title.is_empty() {
                        send.send(ControlCommand::TaskMessage(
                            dst.to_string(),
                            format!("{} has title '{}'", &url, title.trim()),
                        ))
                        .await?;
                    }
                }
            }
        } else {
            // FIXME: this should be a generic "get the header" code path
        }
    }

    Ok(())
}

#[derive(Debug)]
pub(crate) enum ControlCommand {
    Irc(irc2::Message),
    ServerQuit(String),
    TaskMessage(String, String),
}

#[derive(Debug)]
struct Control {
    startup: Instant,
    settings: Arc<Settings>,
    send: Sender<ClientCommand>,

    last_msg: BTreeMap<(String, String), String>,
    last: HashMap<Prefix, Instant>,
}

impl Control {
    async fn message(&self, dst: &str, msg: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send
            .send(ClientCommand::Message(dst.to_string(), msg.to_string()))
            .await?;
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

    async fn handle_zebot_command(
        &mut self,
        msg: &Message,
        dst: &str,
        cmd: &str,
        _args: &[&str],
        send: Sender<ControlCommand>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let cmd = cmd.split_ascii_whitespace().next().unwrap_or("");

        match cmd {
            "!up" | "!uptime" => self.handle_command_uptime(dst).await?,
            "!ver" | "!version" => {
                self.message(
                    dst,
                    &format!("I am version {}, let's not talk about it!", zebot_version()),
                )
                .await?
            }
            "!nag" => self.message(dst, &nag_user(&msg.get_nick())).await?,
            "!echo" => {
                let m = &msg.params[1];
                if m.len() > 6 {
                    let m = &m[6..];
                    if !m.is_empty() {
                        self.message(dst, m).await?;
                    }
                }
            }
            "!exec" | "!sh" | "!shell" | "!powershell" | "!power-shell" => {
                let m = format!("Na aber wer wird denn gleich, {}", msg.get_nick());
                self.message(dst, &m).await?;
            }
            _ => {
                callout(msg.clone(), self.settings.clone(), send.clone()).await?;
            }
        }
        Ok(())
    }

    async fn zebot_answer(
        &mut self,
        msg: &irc2::Message,
        _nick: &str,
        dst: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = Instant::now();
        let last = &mut self.last;
        let pfx = msg.prefix.as_ref().unwrap();
        if last.contains_key(pfx) {
            let last_ts = *last.get(pfx).unwrap();
            last.entry(pfx.clone()).and_modify(|x| *x = now);
            if now.duration_since(last_ts) < Duration::from_secs(2) {
                return Ok(());
            }
        } else {
            last.entry(pfx.clone()).or_insert_with(|| now);
        }

        // It would seem, I need some utility functions to retrieve message semantics
        let m = if thread_rng().gen_bool(0.93) {
            nag_user(&msg.get_nick())
        } else {
            format!("Hey {}", &msg.get_nick())
        };

        self.send
            .send(ClientCommand::Message(dst.to_string(), m))
            .await?;

        Ok(())
    }

    async fn handle_privmsg(
        &mut self,
        msg: &irc2::Message,
        send: Sender<ControlCommand>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let cmd = &msg.command;

        if cmd != &CommandCode::PrivMsg {
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

        if text.to_lowercase().contains(&self.settings.nickname) {
            self.zebot_answer(msg, &msg.get_nick(), &dst).await?;
        }

        url_saver(&msg, self.settings.clone()).await?;

        if text
            .split_ascii_whitespace()
            .any(|w| w == self.settings.nickname)
        {
            self.message(&dst, &nag_user(&msg.get_nick())).await?;
        }

        spawn(youtube_title(
            dst.clone(),
            text.clone(),
            send.clone(),
            self.settings.clone(),
        ));

        self.handle_substitute_command(msg).await?;

        if text.starts_with('!') && text.len() > 1 && text.as_bytes()[1].is_ascii_alphanumeric() {
            let textv = text.split_ascii_whitespace().collect::<Vec<_>>();
            self.handle_zebot_command(msg, &dst, text.as_str(), &textv[1..], send.clone())
                .await?;
            return Ok(());
        }

        info!("{}", msg);

        Ok(())
    }

    async fn logon(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send
            .send(ClientCommand::Logon {
                nick: self.settings.nickname.clone(),
                realname: self.settings.realname.clone(),
            })
            .await?;

        if let Some(pwfile) = &self.settings.password_file {
            match tokio::fs::File::open(&pwfile).await {
                Ok(mut f) => {
                    let mut pw = String::new();
                    f.read_to_string(&mut pw).await?;
                    self.send
                        .send(ClientCommand::Message(
                            "NickServ".to_string(),
                            format!("identify {}", pw.trim()),
                        ))
                        .await?;
                }
                Err(e) => warn!("Could not open password file {}: {:?}", &pwfile, e),
            }
        }

        // join initial channels
        for c in self.settings.channels.iter() {
            self.send.send(ClientCommand::Join(c.clone())).await?;
        }

        Ok(())
    }

    async fn handle_irc_command(
        &mut self,
        msg: &irc2::Message,
        answer: Sender<ControlCommand>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let args = &msg.params;
        let argc = args.len();
        let cmd = &msg.command;
        let pfx = &msg.prefix;

        match cmd {
            CommandCode::Notice
                if argc == 2
                    && args[1].contains("Checking Ident")
                    && matches!(pfx, Some(irc2::Prefix::Server(_))) =>
            {
                self.logon().await?
            }

            CommandCode::PrivMsg => self.handle_privmsg(msg, answer.clone()).await?,

            CommandCode::Join => {
                self.message(
                    &msg.get_reponse_destination(&self.settings.channels),
                    &greet(&msg.get_nick()),
                )
                .await?
            }

            _ => {
                warn!("Missing handler: {}", msg);
            }
        }

        Ok(())
    }

    async fn handle_substitute_command(
        &mut self,
        msg: &Message,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let nick = msg.get_nick();
        let dst = msg.get_reponse_destination(&self.settings.channels);

        if !msg.params[1].starts_with("!s") && !msg.params[1].starts_with("!S") {
            if msg.params[1].starts_with("\x01ACTION") {
                error!("Ignoring ACTION message");
                return Ok(());
            }
            self.last_msg.insert((dst, nick), msg.params[1].clone());
            return Ok(());
        }

        let re = &msg.params[1][1..];
        let big_s = msg.params[1].chars().nth(1).unwrap_or('_') == 'S';

        let (pat, subst, flags) = if let Some(x) = parse_substitution(re) {
            x
        } else {
            self.send
                .send(ClientCommand::Message(
                    dst,
                    "Could not parse substitution".to_string(),
                ))
                .await?;
            return Ok(());
        };

        let (flags, _save_subst) = if flags.contains('s') {
            (flags.replace("s", ""), true)
        } else {
            (flags, false)
        };

        match regex::Regex::new(&pat) {
            Ok(re) => {
                if let Some(last) = self.last_msg.get(&(dst.clone(), nick.clone())) {
                    let new_msg = if flags.contains('g') {
                        re.replace_all(last, subst.as_str())
                    } else if let Ok(n) = flags.parse::<usize>() {
                        re.replacen(last, n, subst.as_str())
                    } else {
                        re.replace(last, subst.as_str())
                    };

                    if new_msg != last.as_str() {
                        // if save_subst {
                        //     self.last_msg.borrow_mut().insert((dst.clone(), nick.clone()), new_msg.to_string());
                        //     log_error!("{} new last message '{}'", nick, msg.params[1].to_string());
                        // }

                        let new_msg = if big_s {
                            format!("{} meinte: {}", nick, new_msg)
                        } else {
                            new_msg.to_string()
                        };

                        self.send.send(ClientCommand::Message(dst, new_msg)).await?;
                    }
                }
            }

            Err(_) => {
                self.send
                    .send(ClientCommand::Message(
                        dst,
                        "Could not parse regex".to_string(),
                    ))
                    .await?;
                return Ok(());
            }
        }

        Ok(())
    }
}

pub(crate) async fn task(
    mut recv: Receiver<ControlCommand>,
    send: Sender<ClientCommand>,
    control_send: Sender<ControlCommand>,
    settings: Arc<Settings>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut line = String::with_capacity(1024);

    let mut client = Control {
        startup: Instant::now(),
        settings: settings.clone(),
        send: send.clone(),
        last_msg: Default::default(),
        last: Default::default(),
    };

    loop {
        tokio::select! {
            msg = recv.recv() => {
                if let Some(msg) = &msg {
                    match msg {
                        ControlCommand::Irc(msg) => if let Err(e) = client.handle_irc_command(msg, control_send.clone()).await {
                            error!("Client side error: {e:?}");
                        },

                        ControlCommand::ServerQuit(reason) => {
                            recv.close();
                            info!("Server quit: {}", reason);
                            break;
                        }

                        ControlCommand::TaskMessage(dst, msg) => {
                            send.send(ClientCommand::Message(dst.clone(), msg.clone())).await?;
                        }
                    }
                }
            }

            n = stdin.read_line(&mut line) => {
                match n {
                    Err(_) => {
                        warn!("Error reading from stdin... quitting");
                        send.send(ClientCommand::Quit).await?;
                        return Ok(());
                    }
                    Ok(n) if n == 0 => {
                        warn!("Got EOF... quitting");
                        send.send(ClientCommand::Quit).await?;
                        continue;
                    }
                    Ok(_) => (),
                }

                let stripped = line.strip_suffix('\n').unwrap_or(&line);
                send.send(ClientCommand::Message(settings.channels[0].clone(), stripped.to_string())).await?;
                line.clear();
            }
        }
    }

    Ok(())
}
