pub(super) fn shannon_entropy_ascii(token: &str) -> Option<f64> {
    if !token.is_ascii() {
        return None;
    }
    let bytes = token.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] = counts[b as usize].saturating_add(1);
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        entropy -= p * p.log2();
    }
    Some(entropy)
}

pub(super) fn is_candidate_secret_token(token: &str) -> bool {
    token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
}

pub(super) fn is_luhn_valid_card_number(text: &str) -> bool {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    if digits.iter().all(|d| *d == digits[0]) {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for d in digits.iter().rev() {
        let mut v = u32::from(*d);
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum = sum.saturating_add(v);
        double = !double;
    }
    sum.is_multiple_of(10)
}

pub(super) fn is_valid_ssn_fragments(text: &str) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let area: u32 = parts[0].parse().unwrap_or(0);
    let group: u32 = parts[1].parse().unwrap_or(0);
    let serial: u32 = parts[2].parse().unwrap_or(0);
    if area == 0 || area == 666 || (900..=999).contains(&area) {
        return false;
    }
    if group == 0 || serial == 0 {
        return false;
    }
    true
}

pub(super) fn is_valid_ssn_compact(text: &str) -> bool {
    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }
    let area: u32 = digits.get(0..3).and_then(|s| s.parse().ok()).unwrap_or(0);
    let group: u32 = digits.get(3..5).and_then(|s| s.parse().ok()).unwrap_or(0);
    let serial: u32 = digits.get(5..9).and_then(|s| s.parse().ok()).unwrap_or(0);
    if area == 0 || area == 666 || (900..=999).contains(&area) {
        return false;
    }
    if group == 0 || serial == 0 {
        return false;
    }
    true
}
