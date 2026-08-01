#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GlobToken {
    Literal(char),
    AnyNonNewline,
    StarNonSlash,
    StarNonNewline,
}

pub(crate) fn tokenize(pattern: &str) -> Vec<GlobToken> {
    let mut chars = pattern.chars().peekable();
    let mut tokens = Vec::with_capacity(pattern.chars().count());
    while let Some(ch) = chars.next() {
        match ch {
            '*' if matches!(chars.peek(), Some('*')) => {
                let _ = chars.next();
                tokens.push(GlobToken::StarNonNewline);
            }
            '*' => tokens.push(GlobToken::StarNonSlash),
            '?' => tokens.push(GlobToken::AnyNonNewline),
            literal => tokens.push(GlobToken::Literal(literal)),
        }
    }
    tokens
}

pub(crate) fn regex_source(pattern: &str) -> String {
    let mut regex = String::from("^");
    for token in tokenize(pattern) {
        match token {
            GlobToken::StarNonNewline => regex.push_str(".*"),
            GlobToken::StarNonSlash => regex.push_str("[^/]*"),
            GlobToken::AnyNonNewline => regex.push('.'),
            GlobToken::Literal(ch)
                if matches!(
                    ch,
                    '.' | '+' | '(' | ')' | '{' | '}' | '[' | ']' | '^' | '$' | '|' | '\\'
                ) =>
            {
                regex.push('\\');
                regex.push(ch);
            }
            GlobToken::Literal(ch) => regex.push(ch),
        }
    }
    regex.push('$');
    regex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenization_preserves_star_pairing_and_regex_escaping() {
        assert_eq!(
            tokenize("a***?"),
            vec![
                GlobToken::Literal('a'),
                GlobToken::StarNonNewline,
                GlobToken::StarNonSlash,
                GlobToken::AnyNonNewline,
            ]
        );
        assert_eq!(regex_source("a.**"), "^a\\..*$");
    }
}
