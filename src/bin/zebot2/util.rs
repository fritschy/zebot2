use json::JsonValue;
use nanorand::{Rng, tls_rng};
use std::fmt::Display;
use std::io;
use std::io::{BufReader, Read};
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

    let s = PATS[gen_index(&mut tls_rng(), PATS.len())];
    s.to_string().replace("{}", nick)
}

pub(crate) fn nag_user(nick: &str) -> String {
    fn doit(nick: &str) -> Result<String, io::Error> {
        let nick = nick.replace(|x: char| !x.is_alphanumeric(), "_");
        let nag_file = format!("nag-{}.txt", nick);
        let f = std::fs::File::open(&nag_file).map_err(|e| {
            error!("Could not open nag-file '{}'", &nag_file);
            e
        })?;
        let mut l = String::new();
        if let Ok(_n) = BufReader::new(f).read_to_string(&mut l) {
            let l = l.lines().collect::<Vec<_>>();
            if !l.is_empty() {
                let m = l[gen_index(&mut tls_rng(), l.len())];
                return Ok(format!("Hey {}, {}", nick, m));
            }
        }
        Ok(format!("Hey {}", nick))
    }

    doit(nick).unwrap_or_else(|_| format!("Hey {}", nick))
}

// This is straight from crate rand
// Sample a number uniformly between 0 and `ubound`. Uses 32-bit sampling where
// possible, primarily in order to produce the same output on 32-bit and 64-bit
// platforms.
#[inline]
fn gen_index<R: Rng<8> + ?Sized>(rng: &mut R, ubound: usize) -> usize {
    if ubound <= (core::u32::MAX as usize) {
        rng.generate_range(0..ubound as u32) as usize
    } else {
        rng.generate_range(0..ubound)
    }
}
