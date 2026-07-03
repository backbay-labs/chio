pub(super) const MAX_QUOTED_SCALAR_WHITESPACE_RUN: usize = 64;
pub(super) const MAX_PLAIN_SCALAR_KEY_WHITESPACE_RUN: usize = 5;
pub(super) const MAX_PLAIN_SCALAR_VALUE_WHITESPACE_RUN: usize = 64;

pub(super) fn has_non_mapping_document_start(input: &str) -> bool {
    for line in input.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        if trimmed == "---" || trimmed == "..." {
            continue;
        }

        let document_start = trimmed.strip_prefix("---").map(str::trim_start);
        let mut candidate = strip_inline_comment(document_start.unwrap_or(trimmed)).trim();
        candidate = strip_yaml_node_properties(candidate);
        if candidate.is_empty() || candidate.starts_with('#') {
            continue;
        }
        if candidate.starts_with('{')
            || explicit_mapping_key_start(candidate)
            || structural_mapping_colon_index(candidate).is_some()
        {
            return false;
        }
        return true;
    }

    false
}

pub(super) fn has_unclosed_double_quoted_value_scalar(input: &str) -> bool {
    let mut open_double_quote_indent: Option<usize> = None;
    let mut block_scalar_parent_indent: Option<usize> = None;

    for line in input.lines() {
        let indent = leading_whitespace_len(line);
        let trimmed = line.trim_start();
        if let Some(parent_indent) = block_scalar_parent_indent {
            if trimmed.is_empty() || indent > parent_indent {
                continue;
            }
            block_scalar_parent_indent = None;
        }

        if open_double_quote_indent.is_none() {
            if let Some(parent_indent) = block_scalar_parent_indent_start(line) {
                block_scalar_parent_indent = Some(parent_indent);
                continue;
            }
        }

        let scan_from = if open_double_quote_indent.is_some() {
            0
        } else if let Some(start) = double_quoted_value_start(line) {
            open_double_quote_indent = Some(indent);
            start + 1
        } else {
            continue;
        };

        if double_quote_state_closes_on_line(line, scan_from) {
            open_double_quote_indent = None;
        }
    }

    open_double_quote_indent.is_some()
}

pub(super) fn has_libyml_scalar_join_overflow_risk(input: &str) -> bool {
    has_libyml_plain_scalar_join_overflow_risk(input)
        || has_libyml_quoted_scalar_join_overflow_risk(input)
}

pub(super) fn explicit_mapping_key_start(candidate: &str) -> bool {
    let Some(rest) = candidate.strip_prefix('?') else {
        return false;
    };

    rest.is_empty()
        || match rest.chars().next() {
            Some(ch) => ch.is_whitespace(),
            None => true,
        }
}

pub(super) fn strip_yaml_node_properties(mut candidate: &str) -> &str {
    loop {
        let trimmed = candidate.trim_start();
        let Some(first) = trimmed.chars().next() else {
            return trimmed;
        };
        if first != '&' && first != '!' {
            return trimmed;
        }
        let token_end = trimmed
            .char_indices()
            .find_map(|(index, ch)| ch.is_whitespace().then_some(index))
            .unwrap_or(trimmed.len());
        candidate = &trimmed[token_end..];
    }
}

pub(super) fn has_libyml_plain_scalar_join_overflow_risk(input: &str) -> bool {
    let mut block_scalar_parent_indent: Option<usize> = None;
    let mut plain_value_parent_indent: Option<usize> = None;

    for line in input.lines() {
        let indent = leading_whitespace_len(line);
        let trimmed = line.trim_start();
        if let Some(parent_indent) = block_scalar_parent_indent {
            if trimmed.is_empty() || indent > parent_indent {
                continue;
            }
            block_scalar_parent_indent = None;
        }

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if plain_value_parent_indent.is_some_and(|parent_indent| indent <= parent_indent) {
            plain_value_parent_indent = None;
        }
        if let Some(parent_indent) = block_scalar_parent_indent_start(line) {
            block_scalar_parent_indent = Some(parent_indent);
            plain_value_parent_indent = None;
            continue;
        }

        if let Some(colon_index) = structural_mapping_colon_index(line) {
            plain_value_parent_indent = None;
            if plain_scalar_text_has_join_overflow_risk(&line[..colon_index]) {
                return true;
            }
            let plain_value = strip_inline_comment(&line[colon_index + 1..]);
            if plain_scalar_value_has_join_overflow_risk(plain_value) {
                return true;
            }
            if plain_scalar_can_continue(plain_value) {
                plain_value_parent_indent = Some(indent);
            }
        } else if plain_value_parent_indent.is_some_and(|parent_indent| indent > parent_indent) {
            if plain_scalar_value_has_join_overflow_risk(trimmed) {
                return true;
            }
        } else if plain_scalar_text_has_join_overflow_risk(trimmed) {
            return true;
        }
    }

    false
}

pub(super) fn plain_scalar_text_has_join_overflow_risk(input: &str) -> bool {
    plain_scalar_text_has_join_overflow_risk_with_limit(
        input,
        MAX_PLAIN_SCALAR_KEY_WHITESPACE_RUN + 1,
    )
}

pub(super) fn plain_scalar_value_has_join_overflow_risk(input: &str) -> bool {
    plain_scalar_text_has_join_overflow_risk_with_limit(
        input,
        MAX_PLAIN_SCALAR_VALUE_WHITESPACE_RUN + 1,
    )
}

pub(super) fn plain_scalar_text_has_join_overflow_risk_with_limit(
    input: &str,
    minimum_run: usize,
) -> bool {
    let trimmed = input.trim();
    if !plain_scalar_can_continue(trimmed) {
        return false;
    }

    has_ascii_whitespace_run(trimmed, minimum_run)
}

pub(super) fn plain_scalar_can_continue(input: &str) -> bool {
    let trimmed = input.trim();
    !trimmed.is_empty()
        && !trimmed.starts_with('"')
        && !trimmed.starts_with('\'')
        && !trimmed.starts_with('[')
        && !trimmed.starts_with('{')
        && !trimmed.starts_with('-')
}

pub(super) fn has_ascii_whitespace_run(input: &str, minimum_run: usize) -> bool {
    let mut run = 0usize;
    for ch in input.chars() {
        if ch.is_ascii_whitespace() {
            run += 1;
            if run >= minimum_run {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

pub(super) fn has_libyml_quoted_scalar_join_overflow_risk(input: &str) -> bool {
    let mut block_scalar_parent_indent: Option<usize> = None;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut whitespace_run = 0usize;

    let mut lines = input.lines().peekable();
    while let Some(line) = lines.next() {
        if !in_single && !in_double {
            let indent = leading_whitespace_len(line);
            let trimmed = line.trim_start();
            if let Some(parent_indent) = block_scalar_parent_indent {
                if trimmed.is_empty() || indent > parent_indent {
                    continue;
                }
                block_scalar_parent_indent = None;
            }

            if trimmed.starts_with('#') {
                continue;
            }
            if let Some(parent_indent) = block_scalar_parent_indent_start(line) {
                block_scalar_parent_indent = Some(parent_indent);
                continue;
            }
        }

        let mut chars = line.char_indices().peekable();
        let mut previous_is_whitespace = false;
        while let Some((index, ch)) = chars.next() {
            if in_single {
                if ch == '\'' {
                    if matches!(chars.peek(), Some((_, '\''))) {
                        let _ = chars.next();
                        whitespace_run = 0;
                    } else {
                        in_single = false;
                        whitespace_run = 0;
                    }
                } else if ch.is_ascii_whitespace() {
                    whitespace_run += 1;
                    if whitespace_run > MAX_QUOTED_SCALAR_WHITESPACE_RUN {
                        return true;
                    }
                } else {
                    whitespace_run = 0;
                }
                previous_is_whitespace = false;
                continue;
            }

            if escaped {
                escaped = false;
                whitespace_run = 0;
                previous_is_whitespace = false;
                continue;
            }

            if in_double {
                match ch {
                    '\\' => {
                        escaped = true;
                        whitespace_run = 0;
                    }
                    '"' => {
                        in_double = false;
                        whitespace_run = 0;
                    }
                    ch if ch.is_ascii_whitespace() => {
                        whitespace_run += 1;
                        if whitespace_run > MAX_QUOTED_SCALAR_WHITESPACE_RUN {
                            return true;
                        }
                    }
                    _ => {
                        whitespace_run = 0;
                    }
                }
                previous_is_whitespace = false;
                continue;
            }

            if ch == '#' && previous_is_whitespace {
                break;
            }
            if ch == '\'' && quote_starts_yaml_scalar(line, index) {
                in_single = true;
                whitespace_run = 0;
                previous_is_whitespace = false;
                continue;
            }
            if ch == '"' && quote_starts_yaml_scalar(line, index) {
                in_double = true;
                whitespace_run = 0;
                previous_is_whitespace = false;
                continue;
            }
            previous_is_whitespace = ch.is_ascii_whitespace();
        }

        if in_single || in_double {
            if escaped {
                escaped = false;
            } else if lines.peek().is_some() {
                whitespace_run += 1;
                if whitespace_run > MAX_QUOTED_SCALAR_WHITESPACE_RUN {
                    return true;
                }
            }
        }
    }

    false
}

pub(super) fn quote_starts_yaml_scalar(line: &str, quote_index: usize) -> bool {
    let before_quote = line[..quote_index].trim_end();
    let Some(previous) = before_quote.chars().last() else {
        return true;
    };

    matches!(previous, ':' | '[' | '{' | ',') || sequence_item_scalar_prefix(before_quote)
}

pub(super) fn leading_whitespace_len(input: &str) -> usize {
    input
        .chars()
        .take_while(|ch| ch.is_ascii_whitespace() && *ch != '\n')
        .map(char::len_utf8)
        .sum()
}

pub(super) fn block_scalar_parent_indent_start(line: &str) -> Option<usize> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return None;
    }

    if sequence_block_scalar_start(trimmed) {
        return Some(leading_whitespace_len(line));
    }

    let colon_index = structural_mapping_colon_index(line)?;
    let after_colon = line[colon_index + 1..].trim_start();
    if !(after_colon.starts_with('|') || after_colon.starts_with('>')) {
        return None;
    }

    Some(leading_whitespace_len(line))
}

pub(super) fn sequence_block_scalar_start(trimmed_line: &str) -> bool {
    let Some(rest) = trimmed_line.strip_prefix('-') else {
        return false;
    };
    let Some(separator) = rest.chars().next() else {
        return false;
    };
    if !separator.is_ascii_whitespace() {
        return false;
    }

    let after_dash = rest.trim_start();
    after_dash.starts_with('|') || after_dash.starts_with('>')
}

pub(super) fn double_quoted_value_start(line: &str) -> Option<usize> {
    if line.trim_start().starts_with('#') {
        return None;
    }

    if let Some(colon_index) = structural_mapping_colon_index(line) {
        let after_colon = &line[colon_index + 1..];
        let value_offset = after_colon.len() - after_colon.trim_start().len();
        let value_index = colon_index + 1 + value_offset;
        return line[value_index..].starts_with('"').then_some(value_index);
    }

    let quote_index = line.find('"')?;
    let prefix = &line[..quote_index];

    sequence_item_scalar_prefix(prefix).then_some(quote_index)
}

pub(super) fn sequence_item_scalar_prefix(prefix: &str) -> bool {
    let mut rest = prefix.trim_start();

    loop {
        let Some(after_dash) = rest.strip_prefix('-') else {
            return false;
        };

        let Some(separator) = after_dash.chars().next() else {
            return true;
        };
        if !separator.is_ascii_whitespace() {
            return false;
        }

        rest = after_dash.trim_start();
        if rest.is_empty() {
            return true;
        }
        if !rest.starts_with('-') {
            return false;
        }
    }
}

pub(super) fn structural_mapping_colon_index(line: &str) -> Option<usize> {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut chars = line.char_indices().peekable();

    while let Some((index, ch)) = chars.next() {
        if in_single {
            if ch == '\'' {
                if matches!(chars.peek(), Some((_, '\''))) {
                    let _ = chars.next();
                } else {
                    in_single = false;
                }
            }
            continue;
        }

        if in_double {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            continue;
        }

        match ch {
            '\'' => in_single = true,
            '"' => in_double = true,
            ':' if yaml_mapping_separator(chars.peek().map(|(_, next)| *next)) => {
                return Some(index);
            }
            _ => {}
        }
    }

    None
}

pub(super) fn yaml_mapping_separator(next: Option<char>) -> bool {
    match next {
        Some(ch) => ch.is_whitespace(),
        None => true,
    }
}

pub(super) fn double_quote_state_closes_on_line(line: &str, mut scan_from: usize) -> bool {
    loop {
        let Some(close_offset) = first_unescaped_double_quote(&line[scan_from..]) else {
            return false;
        };
        let after_close = scan_from + close_offset + 1;
        let rest_before_comment = strip_inline_comment(&line[after_close..]);
        let Some(next_quote_offset) = first_unescaped_double_quote(rest_before_comment) else {
            return true;
        };
        scan_from = after_close + next_quote_offset + 1;
    }
}

pub(super) fn first_unescaped_double_quote(input: &str) -> Option<usize> {
    let mut escaped = false;
    for (index, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(index);
        }
    }

    None
}

pub(super) fn strip_inline_comment(input: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut previous_is_whitespace = false;
    let mut chars = input.char_indices().peekable();

    while let Some((index, ch)) = chars.next() {
        if in_single {
            if ch == '\'' {
                if matches!(chars.peek(), Some((_, '\''))) {
                    let _ = chars.next();
                } else {
                    in_single = false;
                }
            }
            previous_is_whitespace = false;
            continue;
        }

        if escaped {
            escaped = false;
            previous_is_whitespace = false;
            continue;
        }

        if in_double {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            previous_is_whitespace = false;
            continue;
        }

        if ch == '\'' {
            in_single = true;
            previous_is_whitespace = false;
            continue;
        }
        if ch == '"' {
            in_double = true;
            previous_is_whitespace = false;
            continue;
        }
        if ch == '#' && previous_is_whitespace {
            return &input[..index];
        }
        previous_is_whitespace = ch.is_ascii_whitespace();
    }

    input
}
