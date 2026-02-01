use std::{borrow::Cow, sync::LazyLock};

use regex::{Regex, RegexSet};

use super::ip_filtering::filter_ips;

// A macro to allow for &'static str returns
macro_rules! censor {
    ($kind:literal) => {
        concat!("-censored(", $kind, ")-")
    };
}

#[tracing::instrument(skip_all)]
pub fn parse_line<'a>(line: &'a str) -> Cow<'a, str> {
    let line = line.trim();

    if line.is_empty() {
        return censor!("empty_line").into();
    }

    if !line.starts_with('[') {
        return censor!("no_ts_start").into();
    }

    let Some((timestamp, contents)) = line.split_once(']') else {
        return censor!("no_category_colon").into(); // Matching PHP
    };

    static TIMESTAMP_REGEX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^([0-9]{2}:[0-9]{2}:[0-9]{2}|[0-9]{2,4}-[0-9]{2,4}-[0-9]{2,4} [0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,3})+)$",
        ).unwrap()
    });
    if !TIMESTAMP_REGEX.is_match(&timestamp[1..]) {
        return censor!("no_ts_regex_match").into();
    }

    if contents.starts_with(" Starting up round ID ") {
        return Cow::Borrowed(line);
    }

    let mut words = contents.split(' ');
    if words.next() != Some("") {
        return censor!("no_space_after_timestamp").into();
    }

    let log_type = {
        let next_word = words.next().expect("out of words");
        if !next_word.ends_with(':') {
            return censor!("no_category_colon").into();
        }

        if next_word == "GAME-COMPAT:" {
            match words.next() {
                Some(next_word) => next_word,
                None => return censor!("game_compat_no_followup").into(),
            }
        } else {
            next_word
        }
    };

    match log_type[0..(log_type.len() - 1)].trim_start_matches("GAME-") {
        "ACCESS" => match words.next() {
            Some("Login:") => {
                let mut words_vec = words.collect::<Vec<_>>();

                let ip_cid_index = words_vec.len() - 4;
                words_vec[ip_cid_index] = censor!("ip/cid");

                Cow::Owned(format!(
                    "{timestamp}] {log_type} Login: {}",
                    words_vec.join(" ")
                ))
            }

            Some("Failed") => censor!("invalid connection data").into(),

            _ => Cow::Borrowed(line),
        },

        "ADMIN" => {
            let remaining = words.collect::<Vec<_>>().join(" ");

            static REGEX_SET: LazyLock<RegexSet> = LazyLock::new(|| {
                RegexSet::new([
                    r"^HELP:",
                    r"^PM:",
                    r"^ASAY:",
                    r"^<a",
                    r"^.*/\(.*\) : ",
                    r"^.*/\(.*\) added note ",
                    r"^.*/\(.*\) removed a note ",
                    r"^.*/\(.*\) has added ",
                    r"^.*/\(.*\) has edited ",
                    r#"^[^:]*/\(.*\) ".*""#,
                ])
                .unwrap()
            });

            if REGEX_SET.is_match(&remaining) {
                return censor!("asay/apm/ahelp/notes/etc").into();
            }

            Cow::Borrowed(line)
        }

        "ADMINPRIVATE" => censor!("private logtype").into(),

        "TOPIC" => censor!("world_topic logs").into(),

        "SQL" => censor!("sql logs").into(),

        _ => Cow::Borrowed(line),
    }
}

pub fn process_game_log(contents: String) -> String {
    filter_ips(&contents)
        .lines()
        .map(parse_line)
        .fold(String::new(), |a, b| a + &b + "\n")
}
