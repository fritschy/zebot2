use json::JsonValue;
use rand::prelude::IteratorRandom;
use rand::thread_rng;
use std::fmt::Display;
use std::io;
use std::io::{BufRead, BufReader};
use tracing::error;

pub(crate) fn text_box<T: Display, S: Display>(
    mut lines: impl Iterator<Item = T>,
    header: Option<S>,
) -> impl Iterator<Item = String> {
    let mut state = 0;
    std::iter::from_fn(move || match state {
        0 => {
            state += 1;
            if let Some(ref h) = header {
                Some(format!(",-------[ {} ]", h))
            } else {
                Some(",-------".to_string())
            }
        }

        1 => match lines.next() {
            None => {
                state += 1;
                Some("`-------".to_string())
            }
            Some(ref next) => Some(format!("| {}", next)),
        },

        _ => None,
    })
}

pub(crate) fn is_json_flag_set(jv: &JsonValue) -> bool {
    jv.as_bool().unwrap_or(false) || jv.as_number().unwrap_or_else(|| 0.into()) != 0
}

pub(crate) fn parse_substitution(re: &str) -> Option<(String, String, String)> {
    let mut s = 0; // state, see below, can only increment
    let mut sep = '\0';
    let mut pat = String::with_capacity(re.len());
    let mut subst = String::with_capacity(re.len());
    let mut flags = String::with_capacity(re.len());
    for c in re.chars() {
        match s {
            0 => {
                if c != 's' && c != 'S' {
                    error!("Not a substitution");
                    return None;
                }
                s = 1;
            }

            1 => {
                sep = c;
                s = 2;
            }

            2 => {
                if c == sep {
                    s = 3;
                } else {
                    pat.push(c);
                }
            }

            3 => {
                if c == sep {
                    s = 4;
                } else {
                    subst.push(c);
                }
            }

            4 => match c {
                'g' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | 's' => {
                    flags.push(c);
                }
                _ => {
                    error!("Invalid flags");
                    return None;
                }
            },

            _ => {
                error!("Invalid state parsing re");
                return None;
            }
        }
    }

    Some((pat, subst, flags))
}

pub fn zebot_version() -> String {
    // See build.rs
    let rev_info = env!("GIT_REV_INFO");
    let pkg_ver = env!("CARGO_PKG_VERSION");
    if rev_info != "0" {
        format!("{} {}", pkg_ver, rev_info)
    } else {
        pkg_ver.to_string()
    }
}

pub(crate) fn greet(nick: &str) -> String {
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

pub(crate) fn nag_user(nick: &str) -> String {
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

    doit(nick).unwrap_or_else(|_| format!("Hey {}", nick))
}
