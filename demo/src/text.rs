//! Text shaping for a narrow screen with a fixed-width font.

/// Splits `s` into lines of at most `cols` characters. Breaks at spaces when a
/// line has one, and anywhere otherwise, since IDs and URLs have none.
pub fn wrap(s: &str, cols: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in s.split(' ').filter(|w| !w.is_empty()) {
        let joined = if line.is_empty() { word.chars().count() } else { line.chars().count() + 1 + word.chars().count() };
        if joined <= cols {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
            continue;
        }
        if !line.is_empty() {
            lines.push(std::mem::take(&mut line));
        }
        let mut rest: Vec<char> = word.chars().collect();
        while rest.len() > cols {
            lines.push(rest.drain(..cols).collect());
        }
        line = rest.into_iter().collect();
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// `secs` as `m:ss`, clamped at zero.
pub fn countdown(secs: i64) -> String {
    let secs = secs.max(0);
    format!("{}:{:02}", secs / 60, secs % 60)
}

/// The first six and last four characters, when `s` is longer than `max`.
pub fn abbreviate(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s.to_owned();
    }
    let head: String = chars[..6].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}...{tail}")
}

/// `url` without its `https://` or `http://`.
pub fn without_scheme(url: &str) -> &str {
    url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")).unwrap_or(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_breaks_long_words_anywhere() {
        assert_eq!(
            wrap("spiffe://prod.cavallaro.local/iot/defakto-demo", 26),
            vec!["spiffe://prod.cavallaro.lo", "cal/iot/defakto-demo"]
        );
    }

    #[test]
    fn wrap_prefers_spaces() {
        assert_eq!(wrap("invalid_grant: device code expired", 20), vec!["invalid_grant:", "device code expired"]);
    }

    #[test]
    fn wrap_keeps_short_text_whole() {
        assert_eq!(wrap("Hi, Dan!", 26), vec!["Hi, Dan!"]);
        assert_eq!(wrap("", 26), Vec::<String>::new());
    }

    #[test]
    fn wrap_never_drops_characters() {
        let s = "a bb ccccccccccccccc dddd e";
        let joined: String = wrap(s, 6).concat();
        assert_eq!(joined.replace(' ', ""), s.replace(' ', ""));
        assert!(wrap(s, 6).iter().all(|l| l.chars().count() <= 6));
    }

    #[test]
    fn countdown_formats_minutes_and_seconds() {
        assert_eq!(countdown(246), "4:06");
        assert_eq!(countdown(59), "0:59");
        assert_eq!(countdown(-5), "0:00");
    }

    #[test]
    fn abbreviate_keeps_head_and_tail() {
        assert_eq!(abbreviate("7f3a9e00-1111-2222-3333-44445555c21b", 20), "7f3a9e...c21b");
        assert_eq!(abbreviate("short", 20), "short");
    }

    #[test]
    fn scheme_is_dropped() {
        assert_eq!(without_scheme("https://pocket-id.o.cavnet.cloud"), "pocket-id.o.cavnet.cloud");
        assert_eq!(without_scheme("http://x/y"), "x/y");
        assert_eq!(without_scheme("idp.example"), "idp.example");
    }
}
