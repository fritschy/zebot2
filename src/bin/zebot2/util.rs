use std::fmt::Display;
use json::JsonValue;
use tracing::error;

pub(crate) fn text_box<T: Display, S: Display>(
    mut lines: impl Iterator<Item=T>,
    header: Option<S>,
) -> impl Iterator<Item=String> {
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
