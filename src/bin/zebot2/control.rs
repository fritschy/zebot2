use std::error::Error;
use std::fmt::Display;
use std::io;
use std::io::BufReader;
use std::sync::Arc;
use std::time::{Duration, Instant};
use json::JsonValue;
use nom::AsBytes;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use rand::prelude::*;
use std::io::BufRead;
use std::path::Path;
use std::thread::sleep;
use chrono::{Local};
use irc2::Message;
use textwrap::word_splitters::NoHyphenation;
use tokio::spawn;
use url::Url;

use crate::Settings;
use crate::client::{ClientCommand};
use crate::util::{is_json_flag_set, text_box};

#[derive(Debug)]
pub(crate) enum ControlCommand {
    Irc(irc2::Message),
    ServerQuit(String),
    TaskMessage((String, String)),
}

#[derive(Debug)]
struct Client<'a> {
    startup: Instant,
    settings: &'a Settings,
    send: Sender<ClientCommand>,
}

async fn url_saver(msg: &irc2::Message, settings: &Settings) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut filename = String::new();
    for x in settings.extra_opts.iter() {
        if let Some(x) = x.strip_prefix("url_store=") {
            filename = x.to_string();
            break;
        }
    }

    if filename.is_empty() {
        filename = "urls.txt".to_string();
    }

    let mut f = tokio::fs::OpenOptions::new()
        .truncate(false)
        .create(true)
        .write(true)
        .read(false)
        .append(true)
        .open(&filename).await?;

    for word in msg.params[1].split_ascii_whitespace() {
        if let Ok(url) = Url::parse(word) {
            let nick = msg.get_nick();
            let chan = msg.get_reponse_destination(&settings.channels);
            info!("Got an url from {} {}: {}", &chan, &nick, url);
            let line = format!("{}\t{}\t{}\t{}\n", Local::now().to_rfc3339(), chan, nick, url);
            f.write_all(line.as_bytes()).await?;
        }
    }

    Ok(())
}

/*
struct SubstituteLastHandler {
    last_msg: RefCell<HashMap<(String, String), String>>,
}

impl SubstituteLastHandler {
    fn new() -> Self {
        SubstituteLastHandler {
            last_msg: RefCell::new(HashMap::new()),
        }
    }
}

impl MessageHandler for SubstituteLastHandler {
    fn handle(
        &self,
        ctx: &Context,
        msg: &Message,
    ) -> Result<HandlerResult, io::Error> {
        let nick = msg.get_nick();
        let dst = msg.get_reponse_destination(&block_on(async { ctx.joined_channels.read().await }));

        if !msg.params[1].starts_with("!s") && !msg.params[1].starts_with("!S") {
            if msg.params[1].starts_with("\x01ACTION") {
                log_error!("Ignoring ACTION message");
                return Ok(HandlerResult::NotInterested);
            }
            self.last_msg
                .borrow_mut()
                .insert((dst, nick), msg.params[1].clone());
            return Ok(HandlerResult::NotInterested);
        }

        let re = &msg.params[1][1..];
        let big_s = msg.params[1].chars().nth(1).unwrap_or('_') == 'S';

        let (pat, subst, flags) = if let Some(x) = parse_substitution(re) {
            x
        } else {
            send.send(ControlCommand::TaskDone(Some((&dst, "Could not parse substitution");
            return Ok(HandlerResult::Handled);
        };

        let (flags, _save_subst) = if flags.contains('s') {
            (flags.replace("s", ""), true)
        } else {
            (flags, false)
        };

        match regex::Regex::new(&pat) {
            Ok(re) => {
                if let Some(last) = self.last_msg.borrow().get(&(dst.clone(), nick.clone())) {
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

                        send.send(ControlCommand::TaskDone(Some((&dst, &new_msg);
                    }
                }
            }

            Err(_) => {
                send.send(ControlCommand::TaskDone(Some((&dst, "Could not parse regex");
                return Ok(HandlerResult::Handled);
            }
        }

        Ok(HandlerResult::Handled)
    }
}

struct ZeBotAnswerHandler {
    last: RefCell<HashMap<Prefix, Instant>>,
}

impl ZeBotAnswerHandler {
    fn new() -> Self {
        Self {
            last: RefCell::new(HashMap::new()),
        }
    }
}

impl MessageHandler for ZeBotAnswerHandler {
    fn handle(
        &self,
        ctx: &Context,
        msg: &Message,
    ) -> Result<HandlerResult, io::Error> {
        if msg.params.len() > 1 && msg.params[1..].iter().any(|x| x.contains(ctx.nick())) {
            let now = Instant::now();
            let mut last = self.last.borrow_mut();
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
            let m = if thread_rng().gen_bool(0.93) {
                nag_user(&msg.get_nick())
            } else {
                format!("Hey {}", &msg.get_nick())
            };

            let dst = msg.get_reponse_destination(&block_on(async {ctx.joined_channels.read().await}));
            send.send(ControlCommand::TaskDone(Some((&dst, &m);
        }

        // Pretend we're not interested
        Ok(HandlerResult::NotInterested)
    }
}

impl MessageHandler for Callouthandler {
}

impl MessageHandler for GreetHandler {
    fn handle(
        &self,
        ctx: &Context,
        msg: &Message,
    ) -> Result<HandlerResult, io::Error> {
        if *ctx.nick() != msg.get_nick() {
            if let CommandCode::Join = msg.command {
                send.send(ControlCommand::TaskDone(Some((&msg.get_reponse_destination(&block_on(async { ctx.joined_channels.read().await })),
                            &greet(&msg.get_nick()),
                );
            }
        }

        Ok(HandlerResult::NotInterested)
    }
}

impl MessageHandler for MiscCommandsHandler {
fn handle(
    &self,
    ctx: &Context,
    msg: &Message,
) -> Result<HandlerResult, io::Error> {
        if msg.params.len() < 2 {
            return Ok(HandlerResult::NotInterested);
        }

        match msg.params[1]
            .split_ascii_whitespace()
            .next()
            .unwrap_or_else(|| msg.params[1].as_ref())
        {
            "!version" | "!ver" => {
                let dst = msg.get_reponse_destination(&block_on(async { ctx.joined_channels.read().await }));
                send.send(ControlCommand::TaskDone(Some((&dst, &format!("I am version {}, let's not talk about it!", zebot_version()));
            }
            "!uptime" | "!up" => {
                let dst = msg.get_reponse_destination(&block_on(async { ctx.joined_channels.read().await }));

                let mut r = String::new();
                let mut u = ctx.start_time.elapsed().as_secs();

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

                send.send(ControlCommand::TaskDone(Some((&dst, &format!("{} uptime", r));
            }
            "!help" | "!commands" => {
                let dst = msg.get_reponse_destination(&block_on(async { ctx.joined_channels.read().await }));
                send.send(ControlCommand::TaskDone(Some((&dst, "I am ZeBot, I can say Hello and answer to !fortune, !bash, !echo and !errno <int>");
            }
            "!echo" => {
                let dst = msg.get_reponse_destination(&block_on(async { ctx.joined_channels.read().await }));
                let m = &msg.params[1];
                if m.len() > 6 {
                    let m = &m[6..];
                    if !m.is_empty() {
                        send.send(ControlCommand::TaskDone(Some((&dst, m);
                    }
                }
            }
            "!exec" | "!sh" | "!shell" | "!powershell" | "!power-shell" => {
                let m = format!("Na aber wer wird denn gleich, {}", msg.get_nick());
                send.send(ControlCommand::TaskDone(Some((
                    msg.get_reponse_destination(&block_on(async { ctx.joined_channels.read().await }))
                        .as_str(),
                    &m,
                );
            }
            _ => return Ok(HandlerResult::NotInterested),
        }

        Ok(HandlerResult::Handled)
    }
}
*/

pub enum HandlerResult {
    Handled,
    NotInterested,
    Error(String),
}

async fn callout(msg: irc2::Message, settings: Settings, send: Sender<ControlCommand>) -> Result<HandlerResult, Box<dyn Error + Send + Sync>> {
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

    if !Path::new(&path).exists() {
        return Ok(HandlerResult::NotInterested);
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
        let s = Instant::now();
        let cmd = Command::new("/usr/bin/timeout").arg("30s").arg(path).args(&args).output().await;
        let s = s.elapsed();

        info!("Handler {} completed in {:?}", command, s);

        match cmd {
            Ok(p) => {
                if !p.status.success() {
                    let dst = msg.get_reponse_destination(&settings.channels);
                    error!("Handler failed with code {}", p.status.code().unwrap());
                    dbg!(&p);
                    send.send(ControlCommand::TaskMessage((dst, "Somehow, that did not work...".to_string()))).await;
                    return;
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
                                send.send(ControlCommand::TaskMessage((dst, "Somehow, that did not work...".to_string()))).await;
                                return;
                            } else if !is_json_flag_set(&response["box"]) {
                                for l in response["lines"].members() {
                                    send.send(ControlCommand::TaskMessage((dst.clone(), l.to_string()))).await;
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
                                    send.send(ControlCommand::TaskMessage((dst.clone(), i))).await;
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
                return;
            }
        }
    });

    Ok(HandlerResult::Handled)
}

fn greet(nick: &str) -> String {
    const PATS: &[&str] = &[
        "Hey {}!",
        "Moin {}, o/",
        "Moin {}, \\o",
        "Moin {}, \\o/",
        "Moin {}, _o/",
        "Moin {}, \\o_",
        "Moin {}, o_/",
        "OI, Ein {}!",
        "{}, n'Moin!",
        "{}, grüß Gott, äh - Zeus! Was gibt's denn Neu's?",
    ];

    if let Some(s) = PATS.iter().choose(&mut thread_rng()) {
        return s.to_string().replace("{}", nick);
    }

    String::from("Hey ") + nick
}

fn nag_user(nick: &str) -> String {
    fn doit(nick: &str) -> Result<String, io::Error> {
        let nick = nick.replace(|x: char| !x.is_alphanumeric(), "_");
        let nag_file = format!("nag-{}.txt", nick);
        let f = std::fs::File::open(&nag_file).map_err(|e| {
            error!("Could not open nag-file '{}'", &nag_file);
            e
        })?;
        let br = BufReader::new(f);
        let l = br.lines();
        let m = l
            .choose(&mut thread_rng())
            .unwrap_or_else(|| Ok("...".to_string()))?;
        Ok(format!("Hey {}, {}", nick, m))
    }

    doit(nick).unwrap_or_else(|x| {
        format!("Hey {}", nick)
    })
}

async fn youtube_title(dst: String, text: String, send: Sender<ControlCommand>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let yt_re = regex::Regex::new(r"https?://((www.)?youtube\.com/watch|youtu.be/)").unwrap();
    for url in text
        .split_ascii_whitespace()
        .filter(|&x| x.starts_with("https://") || x.starts_with("http://")) {
        if yt_re.is_match(url) {
            if let Ok(output) = Command::new("python3")
                // .current_dir("youtube-dl")
                .args(&[
                    "-m", "yt_dlp", "--quiet", "--get-title", "--socket-timeout", "15", url,
                ])
                .output().await {
                let err = String::from_utf8_lossy(output.stderr.as_ref());
                if !err.is_empty() {
                    error!("Got error from youtube-dl: {}", err);
                    send.send(ControlCommand::TaskMessage((dst.to_string(), format!("Got an error for URL {}, is this a valid video URL?", &url)))).await?;
                } else {
                    let title = String::from_utf8_lossy(output.stdout.as_ref());
                    if !title.is_empty() {
                        send.send(ControlCommand::TaskMessage((dst.to_string(), format!("{} has title '{}'", &url, title.trim())))).await?;
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

impl<'a> Client<'a> {
    async fn message(&self, dst: &str, msg: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send.send(ClientCommand::Message(dst.to_string(), msg.to_string())).await?;
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

    async fn handle_zebot_command(&self, msg: &Message, dst: &str, cmd: &str, args: &[&str], send: Sender<ControlCommand>) -> Result<(), Box<dyn Error + Send + Sync>> {
        match cmd {
            "!up" | "!uptime" => self.handle_command_uptime(dst).await?,
            _ => {
                callout(msg.clone(), self.settings.clone(), send.clone()).await?;
            },
        }
        Ok(())
    }

    async fn handle_privmsg(&self, msg: &irc2::Message, send: Sender<ControlCommand>) -> Result<(), Box<dyn Error + Send + Sync>> {
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

        url_saver(&msg, &self.settings).await?;

        spawn(youtube_title(dst.clone(), text.clone(), send.clone()));

        if text.starts_with('!') && text.len() > 1 && text.as_bytes()[1].is_ascii_alphanumeric() {
            let textv = text.split_ascii_whitespace().collect::<Vec<_>>();
            self.handle_zebot_command(msg, &dst, text.as_str(), &textv[1..], send.clone()).await?;
            return Ok(());
        }

        info!("{}", msg);

        Ok(())
    }

    async fn logon(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send.send(ClientCommand::Logon {nick: self.settings.nickname.clone(), realname: self.settings.realname.clone()}).await?;

        if let Some(pwfile) = &self.settings.password_file {
            match tokio::fs::File::open(&pwfile).await {
                Ok(mut f) => {
                    let mut pw = String::new();
                    f.read_to_string(&mut pw).await?;
                    self.send.send(ClientCommand::Message("NickServ".to_string(), format!("identify {}", pw.trim()))).await?;
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

    async fn handle_irc_command(&self, msg: &irc2::Message, answer: Sender<ControlCommand>) -> Result<(), Box<dyn Error + Send + Sync>> {
        use irc2::command::CommandCode;

        let args = &msg.params;
        let argc = args.len();
        let cmd = &msg.command;
        let pfx = &msg.prefix;

        match cmd {
            CommandCode::Notice if argc == 2
                && args[1].contains("Checking Ident")
                && matches!(pfx, Some(irc2::Prefix::Server(_))) => self.logon().await?,

            CommandCode::PrivMsg => self.handle_privmsg(msg, answer.clone()).await?,

            _ => {
                warn!("Missing handler: {}", msg);
            }
        }

        Ok(())
    }
}

pub(crate) async fn task(mut recv: Receiver<ControlCommand>, send: Sender<ClientCommand>, control_send: Sender<ControlCommand>, settings: Settings) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut line = String::with_capacity(1024);

    let client = Client {startup: Instant::now(), settings: &settings, send: send.clone()};

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

                        ControlCommand::TaskMessage((dst, msg)) => {
                            info!("TaskDone({dst}, {msg})");
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
