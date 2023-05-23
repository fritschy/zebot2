use chrono::Local;
use irc2::command::CommandCode;
use irc2::{Message, Prefix};
use nanorand::{tls_rng, Rng};
use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use textwrap::WordSplitter::NoHyphenation;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::Builder;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};
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
            match url.scheme() {
                "ssh" | "sftp" | "davs" | "smb" | "cifs" | "http" | "https" | "ftp" | "ftps" => {
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
                _ => (),
            }
        }
    }

    Ok(())
}

async fn callout(
    msg: irc2::Message,
    settings: Arc<Settings>,
    client: Sender<ClientCommand>,
) -> Result<HandlerResult, Box<dyn Error + Send + Sync>> {
    if msg.params.len() < 2 || !msg.params[1].starts_with('!') {
        return Ok(HandlerResult::NotInterested);
    }

    let command = msg.params[1][1..]
        .split_ascii_whitespace()
        .next()
        .unwrap_or_default();
    if !command
        .chars()
        .all(|x| x.is_ascii_alphanumeric() || x == '-' || x == '_')
    {
        return Ok(HandlerResult::NotInterested);
    }

    let command = command.to_lowercase();

    let path = format!("./handlers/{}", command);

    {
        let path = Path::new(&path);

        static ATOMIC_ID: AtomicUsize = AtomicUsize::new(1);
        let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);

        // Let's cheat a little ...
        if !(path.exists() && path.metadata()?.permissions().mode() & 0o111 != 0) {
            let dst = msg.get_reponse_destination(&settings.channels);
            client
                .send(ClientCommand::Message(
                    dst,
                    format!("/bin/sh: {}: {}: not found", id, &command),
                ))
                .await?;
            return Ok(HandlerResult::NotInterested);
        }
    }

    let nick = msg.get_nick();
    let args = [nick]
        .into_iter()
        .chain(msg.params.iter().map(|x| x.to_string()))
        .collect::<Vec<_>>();

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
    //   "raw": "raw-irc-proto"       # optional, overrides everything else
    // }

    info!("callout args={args:?}");

    tokio::task::Builder::new()
        .name("callout")
        .spawn(async move {
            async fn wrapper(
                msg: Message,
                command: String,
                path: impl AsRef<Path>,
                args: Vec<String>,
                settings: Arc<Settings>,
                send: Sender<ClientCommand>,
            ) -> Result<(), Box<dyn Error + Send + Sync>> {
                let s = Instant::now();
                let cmd = timeout(
                    Duration::from_secs(30),
                    Command::new(path.as_ref()).args(&args).output(),
                )
                .await;

                let s = s.elapsed();

                let dst = msg.get_reponse_destination(&settings.channels);

                if let Err(e) = cmd {
                    warn!("Handler timed out: {e:}");
                    send.send(ClientCommand::Message(dst, "Handler timed out".to_string()))
                        .await?;
                    return Ok(());
                }
                let cmd = cmd.unwrap();

                info!("Handler {} completed in {:?}", command, s);

                match cmd {
                    Ok(p) => {
                        if !p.status.success() {
                            error!(
                                "Handler failed with code {}: {p:?}",
                                p.status.code().unwrap()
                            );
                            if p.stdout.is_empty() {
                                send.send(ClientCommand::Message(
                                    dst,
                                    "Somehow, that did not work...".to_string(),
                                ))
                                .await?;
                            } else {
                                if let Some(x) = String::from_utf8(p.stdout)
                                    .ok()
                                    .and_then(|s| json::parse(&s).ok())
                                {
                                    if let Some(x) = x.entries().filter(|x| x.0 == "error").next() {
                                        send.send(ClientCommand::Message(
                                            dst,
                                            format!("Handler failed: {}", x.1),
                                        ))
                                        .await?;
                                    } else {
                                        send.send(ClientCommand::Message(
                                            dst,
                                            "Handler failed w/o error".to_string(),
                                        ))
                                        .await?;
                                    }
                                }
                            }
                            return Ok(());
                        }

                        if let Ok(response) = String::from_utf8(p.stdout) {
                            match json::parse(&response) {
                                Ok(response) => {
                                    if let Some(raw) = response["raw"].as_str() {
                                        send.send(ClientCommand::RawMessage(raw.to_string()))
                                            .await?;
                                        return Ok(());
                                    }

                                    let dst = if let Some(dst) = response["dst"].as_str() {
                                        dst.to_string()
                                    } else {
                                        dst
                                    };

                                    const KNOWN_FIELDS: &[&str] = &[
                                        "lines",
                                        "dst",
                                        "box",
                                        "wrap",
                                        "wrap_single_lines",
                                        "title",
                                        "link",
                                    ];

                                    if response.entries().any(|(k, _)| !KNOWN_FIELDS.contains(&k)) {
                                        warn!("Handler response contains unknown fields!");
                                    }

                                    debug!("Response={response:?}");

                                    if let Some(error) = response["error"].as_str() {
                                        send.send(ClientCommand::Message(
                                            dst,
                                            format!("Handler returned an error: {}", error),
                                        ))
                                        .await?;
                                        return Ok(());
                                    } else if !is_json_flag_set(&response["box"]) {
                                        for l in response["lines"].members() {
                                            send.send(ClientCommand::Message(
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
                                            && lines.iter().any(|x| x.len() > 80)
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

                                        for i in text_box(lines.iter(), response["title"].as_str())
                                        {
                                            send.send(ClientCommand::Message(dst.clone(), i))
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
                    }
                }

                Ok(())
            }

            if let Err(e) = wrapper(msg, command, path, args, settings, client).await {
                error!("Callout errored: {e:?}");
            }
        })?;

    Ok(HandlerResult::Handled)
}

async fn youtube_title(
    dst: String,
    text: String,
    client: Sender<ClientCommand>,
    settings: Arc<Settings>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let yt_re = regex::Regex::new(r"https?://((m\.|www\.)?youtube\.com/watch|youtu.be/)").unwrap();
    for url in text
        .split_whitespace()
        .filter(|&x| x.starts_with("https://") || x.starts_with("http://"))
    {
        if yt_re.is_match(url) {
            let py = settings.get_extra("python").unwrap_or("python3");
            let mut cmd_builder = Command::new(py);
            if let Some(youtube_dl_dir) = settings.get_extra("youtube_dl_dir") {
                cmd_builder.current_dir(youtube_dl_dir);
            }

            let module = settings
                .get_extra("youtube_dl_module")
                .unwrap_or("youtube_dl");

            if let Ok(output) = cmd_builder
                .args([
                    "-B", // do not write .pyc files on import
                    "-m",
                    module,
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
                    client
                        .send(ClientCommand::Message(
                            dst.to_string(),
                            format!("Got an error for URL {}, is this a valid video URL?", &url),
                        ))
                        .await?;
                } else {
                    let title = String::from_utf8_lossy(output.stdout.as_ref());
                    if !title.is_empty() {
                        client
                            .send(ClientCommand::Message(
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

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum HandlerResult {
    Handled,
    NotInterested,
}

macro_rules! return_if_handled {
    ($e: expr) => {
        if $e == HandlerResult::Handled {
            return Ok(HandlerResult::Handled);
        }
    };
}

#[derive(Debug)]
pub enum ControlCommand {
    Irc(irc2::Message),
    ServerQuit(String),
}

#[derive(Debug)]
pub struct Control {
    startup: Instant,
    settings: Arc<Settings>,
    client: Sender<ClientCommand>,

    last_msg: BTreeMap<(String, String), String>,
    last: HashMap<Prefix, Instant>,

    pings: HashMap<u64, (String, Instant)>,
}

impl Control {
    pub async fn message(&self, dst: &str, msg: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.client
            .send(ClientCommand::Message(dst.to_string(), msg.to_string()))
            .await?;
        Ok(())
    }

    pub async fn handle_command_uptime(
        &self,
        dst: &str,
    ) -> Result<HandlerResult, Box<dyn Error + Send + Sync>> {
        let mut u = self.startup.elapsed().as_secs();
        let mut r = String::new();

        use std::fmt::Write as _;

        if u >= 3600 * 24 * 365 {
            let y = u / (3600 * 24 * 365);
            write!(r, "{}y", y)?;
            u -= y * 3600 * 24 * 365;
        }

        if u >= 3600 * 24 {
            let d = u / (3600 * 24);
            write!(r, "{}d", d)?;
            u -= d * 3600 * 24;
        }

        let h = u / 3600;
        u -= h * 3600;

        let m = u / 60;
        u -= m * 60;

        write!(r, "{:02}:{:02}:{:02} uptime", h, m, u)?;

        self.message(dst, &r).await?;

        Ok(HandlerResult::Handled)
    }

    pub async fn handle_zebot_command(
        &mut self,
        msg: &Message,
        dst: &str,
        cmd: &str,
        _args: &[&str],
    ) -> Result<HandlerResult, Box<dyn Error + Send + Sync>> {
        let cmd = cmd.split_ascii_whitespace().next().unwrap_or("");

        match cmd {
            "!up" | "!uptime" => return self.handle_command_uptime(dst).await,
            "!ver" | "!version" => {
                return self
                    .message(
                        dst,
                        &format!(
                            "I am {} version {}, let's not talk about it!",
                            env!("CARGO_PKG_NAME"),
                            zebot_version()
                        ),
                    )
                    .await
                    .map(|_| HandlerResult::Handled);
            }
            "!echo" => {
                let m = &msg.params[1];
                if m.len() > 6 {
                    let m = &m[6..];
                    if !m.is_empty() {
                        return self.message(dst, m).await.map(|_| HandlerResult::Handled);
                    }
                }
            }
            "!exec" | "!sh" | "!shell" | "!powershell" | "!power-shell" => {
                let m = format!("Na aber wer wird denn gleich, {}", msg.get_nick());
                return self.message(dst, &m).await.map(|_| HandlerResult::Handled);
            }
            "!ping" => {
                let id: u64 = tls_rng().generate();
                self.pings.insert(
                    id,
                    (
                        msg.get_reponse_destination(&self.settings.channels),
                        Instant::now(),
                    ),
                );
                self.client
                    .send(ClientCommand::RawMessage(format!("PING {id}\r\n")))
                    .await?;
                return Ok(HandlerResult::Handled);
            }
            _ => {
                return_if_handled!(
                    callout(msg.clone(), self.settings.clone(), self.client.clone()).await?
                )
            }
        }

        Ok(HandlerResult::NotInterested)
    }

    pub async fn zebot_answer(
        &mut self,
        msg: &irc2::Message,
        dst: &str,
    ) -> Result<HandlerResult, Box<dyn Error + Send + Sync>> {
        let now = Instant::now();
        let last = &mut self.last;
        let pfx = msg.prefix.as_ref().unwrap();
        if last.contains_key(pfx) {
            let last_ts = *last.get(pfx).unwrap();
            last.entry(pfx.clone()).and_modify(|x| *x = now);
            if now.duration_since(last_ts) < Duration::from_secs(2) {
                return Ok(HandlerResult::NotInterested);
            }
        } else {
            last.entry(pfx.clone()).or_insert_with(|| now);
        }

        // It would seem, I need some utility functions to retrieve message semantics
        let m = if tls_rng().generate::<f32>() < 0.93 {
            nag_user(&msg.get_nick())
        } else {
            format!("Hey {}", &msg.get_nick())
        };

        self.client
            .send(ClientCommand::Message(dst.to_string(), m))
            .await?;

        Ok(HandlerResult::Handled)
    }

    // Handle a "good bot" message, let's not talk about efficiency here...
    pub async fn handle_good_bot(
        &mut self,
        msg: &Message,
        text: &str,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        const REPLIES: &[&str] = &[
            "why, thank you!",
            "thank you",
            "thx(r)[TM] m8!",
            "you're welcome",
            "don't mention it!",
            "sod off...!",
            "irgendwas kann jeder!!2",
        ];

        let text = text.to_lowercase();

        // split into words, normalize them a little
        let words = text
            .split_whitespace()
            .map(|n| n.trim_end_matches(|x: char| x.is_ascii_punctuation() || x.is_numeric()))
            .collect::<Vec<_>>();

        const ATTA_X: &[&str] = &["attaboi", "attaboy", "attagirl", "attadog"];

        // there may be more of these special cases ...
        // Good boy
        if words.iter().any(|f| *f == "いい子" || ATTA_X.contains(f)) {
            self.message(
                &msg.get_reponse_destination(&self.settings.channels),
                &format!(
                    "{}: {}",
                    msg.get_nick(),
                    REPLIES[tls_rng().generate::<usize>() % REPLIES.len()]
                ),
            )
            .await?;
            return Ok(true);
        }

        // Oh, well this sucks!
        const GS: &str = "gŋ";
        const OS: &str = "öoø0°";
        const US: &str = "uüµw";
        const DS: &str = "dđðtŧ";
        const ES: &str = "æ€eäa@r";

        const BS: &str = "bþß";
        const TS: &str = "tŧ";
        const YS: &str = "yi¥";

        let good_re = Regex::new(&format!(
            "[{}]+([{}]+|[{}]+|[{}{}]+)[{}]+([{}]+)?",
            GS, US, OS, OS, ES, DS, ES
        ))
        .unwrap();
        let bot_re = Regex::new(&format!("[{}]+[{}]+[{}]+", BS, OS, TS)).unwrap();
        let boy_re = Regex::new(&format!("[{}]+[{}]+[{}]+", BS, OS, YS)).unwrap();

        // for each pairs of words try to find any match
        if words.windows(2).any(|words| {
            [&good_re, &bot_re]
                .into_iter()
                .zip([&good_re, &boy_re])
                .zip(words)
                .all(|((re1, re2), word)| re1.is_match(word) || re2.is_match(word))
        }) {
            // answer courteously
            self.message(
                &msg.get_reponse_destination(&self.settings.channels),
                &format!(
                    "{}: {}",
                    msg.get_nick(),
                    REPLIES[tls_rng().generate::<usize>() % REPLIES.len()]
                ),
            )
            .await?;
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn handle_japanese_text(
        &mut self,
        msg: &Message,
        text: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // https://translate.google.com/?sl=ja&tl=de&text=+%E5%91%8A%E7%99%BD%E3%82%BF%E3%82%A4%E3%83%A0&op=translate

        // split into words, normalize them a little
        let words = text
            .split_whitespace()
            .map(|n| n.trim_matches(|x: char| x.is_ascii_punctuation() || x.is_numeric()))
            .collect::<Vec<_>>();

        for word in words.iter() {
            if word.chars().all(|x| {
                let x = x as u32;
                (0x4e00..=0x9fbf).contains(&x)
                    || (0x3040..=0x309f).contains(&x)
                    || (0x30a0..=0x30ff).contains(&x)
            }) && !word.is_empty()
            {
                self.message(&msg.get_reponse_destination(&self.settings.channels),
                             &format!("translate {} here: https://translate.google.com/?sl=ja&tl=en&text={}&op=translate",
                                      &word, urlencoding::encode(word))).await?;
            }
        }

        Ok(())
    }

    pub async fn handle_privmsg(
        &mut self,
        msg: &irc2::Message,
    ) -> Result<HandlerResult, Box<dyn Error + Send + Sync>> {
        let cmd = &msg.command;

        if cmd != &CommandCode::PrivMsg {
            return Ok(HandlerResult::NotInterested);
        }

        let args = &msg.params;
        let argc = args.len();
        let dst = msg.get_reponse_destination(&self.settings.channels);

        if argc < 2 || args[1].is_empty() {
            warn!("Improper PRIVMSG: {}", msg);
            return Ok(HandlerResult::NotInterested);
        }

        let text = &args[1];

        if self.handle_good_bot(msg, text).await? {
            return Ok(HandlerResult::NotInterested);
        }

        self.handle_japanese_text(msg, text).await?;

        Builder::new().name("yt-title").spawn(youtube_title(
            dst.clone(),
            text.clone(),
            self.client.clone(),
            self.settings.clone(),
        ))?;

        url_saver(msg, self.settings.clone()).await?;

        if text.starts_with('!') && text.len() > 1 && text.as_bytes()[1].is_ascii_alphanumeric() {
            let textv = text.split_ascii_whitespace().collect::<Vec<_>>();
            return_if_handled!(
                self.handle_zebot_command(msg, &dst, text.as_str(), &textv[1..])
                    .await?
            );
        }

        return_if_handled!(self.handle_substitute_command(msg).await?);

        if text
            .split(|c: char| {
                (c.is_whitespace() || c.is_ascii_punctuation())
                    && !self.settings.nickname.contains(c)
            })
            .any(|w| w == self.settings.nickname)
        {
            return_if_handled!(self.zebot_answer(msg, &dst).await?);
        }

        info!("{}", msg);

        Ok(HandlerResult::NotInterested)
    }

    pub async fn logon(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.client
            .send(ClientCommand::Logon {
                nick: self.settings.nickname.clone(),
                realname: self.settings.realname.clone(),
            })
            .await?;

        sleep(Duration::from_secs(2)).await;

        // join initial channels
        for c in self.settings.channels.iter() {
            self.client.send(ClientCommand::Join(c.clone())).await?;
        }

        Ok(())
    }

    pub async fn nickserv_identify(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(pwfile) = &self.settings.password_file {
            match tokio::fs::File::open(&pwfile).await {
                Ok(mut f) => {
                    let mut pw = String::new();
                    f.read_to_string(&mut pw).await?;
                    self.client
                        .send(ClientCommand::Message(
                            "NickServ".to_string(),
                            format!("identify {}", pw.trim()),
                        ))
                        .await?;
                }
                Err(e) => warn!("Could not open password file {}: {:?}", &pwfile, e),
            }
        }

        Ok(())
    }

    pub async fn handle_irc_command(
        &mut self,
        msg: &irc2::Message,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let args = &msg.params;
        let argc = args.len();
        let cmd = &msg.command;

        match cmd {
            CommandCode::Notice if argc == 2 && args[1].contains("Checking Ident") => {
                self.logon().await?
            }

            CommandCode::Notice
                if argc == 2 && args[1].contains("This nickname is registered.") =>
            {
                self.nickserv_identify().await?
            }

            CommandCode::Generic(code) if code == "PONG" && args.len() == 2 => {
                if let Ok(pid) = args[1].parse::<u64>() {
                    if let Some((dst, t0)) = self.pings.remove(&pid) {
                        self.message(&dst, &format!("{} {:?}", args[0], Instant::now() - t0))
                            .await?;
                    } else {
                        warn!("Could not find ping entry for pong: {msg:?}");
                    }
                } else {
                    warn!("Could not parse ID from pong: {msg:?}");
                }
            }

            CommandCode::PrivMsg => self.handle_privmsg(msg).await.map(|_| ())?,

            CommandCode::Join => {
                if msg.get_nick() != self.settings.nickname {
                    self.message(
                        &msg.get_reponse_destination(&self.settings.channels),
                        &greet(&msg.get_nick()),
                    )
                    .await?
                }
            }

            CommandCode::Ping => (),

            _ => {
                warn!("IRC Command not handled: {}", msg);
            }
        }

        Ok(())
    }

    pub async fn handle_substitute_command(
        &mut self,
        msg: &Message,
    ) -> Result<HandlerResult, Box<dyn Error + Send + Sync>> {
        let nick = msg.get_nick();
        let dst = msg.get_reponse_destination(&self.settings.channels);

        if !msg.params[1].starts_with("!s") && !msg.params[1].starts_with("!S") {
            if msg.params[1].starts_with("\x01ACTION") {
                error!("Ignoring ACTION message");
                return Ok(HandlerResult::NotInterested);
            }
            self.last_msg.insert((dst, nick), msg.params[1].clone());
            return Ok(HandlerResult::NotInterested);
        }

        let re = &msg.params[1][1..];
        let big_s = msg.params[1].chars().nth(1).unwrap_or('_') == 'S';

        let (pat, subst, flags) = if let Some(x) = parse_substitution(re) {
            x
        } else {
            self.client
                .send(ClientCommand::Message(
                    dst,
                    "Could not parse substitution".to_string(),
                ))
                .await?;
            return Ok(HandlerResult::NotInterested);
        };

        let (flags, _save_subst) = if flags.contains('s') {
            (flags.replace('s', ""), true)
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

                        self.client
                            .send(ClientCommand::Message(dst, new_msg))
                            .await?;
                    }
                }
            }

            Err(_) => {
                self.client
                    .send(ClientCommand::Message(
                        dst,
                        "Could not parse regex".to_string(),
                    ))
                    .await?;
                return Ok(HandlerResult::NotInterested);
            }
        }

        Ok(HandlerResult::Handled)
    }

    pub async fn handle_command(&mut self, line: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let line = &line[1..];
        let (cmd, args) = if let Some(space) = line.find(' ') {
            line.split_at(space)
        } else {
            (line, "")
        };

        let args = if args.len() > 1 { &args[1..] } else { args };

        match cmd {
            "help" => {
                println!("Nothing here ... yet!");
            }

            "quote" => {
                info!("raw command '{args}'");
                self.client
                    .send(ClientCommand::RawMessage(format!("{args}\r\n")))
                    .await?;
            }

            _ => {
                info!("raw command '{line}'");
                self.client
                    .send(ClientCommand::RawMessage(format!("{line}\r\n")))
                    .await?;
            }
        }

        Ok(())
    }
}

pub async fn task(
    mut cmd: Receiver<ControlCommand>,
    client: Sender<ClientCommand>,
    settings: Arc<Settings>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut line = String::with_capacity(1024);
    let mut vline = Vec::with_capacity(1024);

    let mut ctrl = Control {
        startup: Instant::now(),
        settings: settings.clone(),
        client: client.clone(),
        last_msg: Default::default(),
        last: Default::default(),
        pings: Default::default(),
    };

    debug!("settings={settings:#?}");

    while !client.is_closed() {
        {
            // cleanup pings, not sure if this is really necessary though.
            let now = Instant::now();
            ctrl.pings
                .retain(|_a, b| !(now > b.1 && now - b.1 > Duration::from_secs(1)));
        }

        // paste this code in their respective places below
        macro_rules! handle_recv {
            ($get_msg:expr) => {
                if let Some(msg) = &$get_msg {
                    match msg {
                        ControlCommand::Irc(msg) => {
                            if let Err(e) = ctrl.handle_irc_command(msg).await {
                                error!("Client side error: {e:?}");
                            }
                        }

                        ControlCommand::ServerQuit(reason) => {
                            cmd.close();
                            info!("Server quit: {}", reason);
                            break;
                        }
                    }
                }
            };
        }

        if settings.no_stdin {
            handle_recv!(cmd.recv().await);
        } else {
            vline.clear();
            line.clear();

            tokio::select! {
                msg = cmd.recv() => {
                    handle_recv!(msg);
                }

                n = stdin.read_until(b'\n', &mut vline) => {
                    match n {
                        Err(_) => {
                            warn!("Error reading from stdin... quitting");
                            client.send(ClientCommand::Quit).await?;
                            return Ok(());
                        }
                        Ok(n) if n == 0 => {
                            warn!("Got EOF... quitting");
                            client.send(ClientCommand::Quit).await?;
                            break;
                        }
                        Ok(_) => {
                            line += &String::from_utf8_lossy(&vline);
                        },
                    }

                    let stripped = line.strip_suffix('\n').unwrap_or(&line);

                    if stripped.starts_with('/') {
                        ctrl.handle_command(stripped).await?;
                    } else {
                        client.send(ClientCommand::Message(settings.channels[0].clone(), stripped.to_string())).await?;
                    }
                    line.clear();
                }
            }
        }
    }

    Ok(())
}
