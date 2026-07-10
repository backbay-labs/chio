pub(super) fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} bytes")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub(super) fn percentile(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (sorted.len() * pct / 100).min(sorted.len() - 1);
    sorted[idx]
}

/// Compute the arithmetic mean of a slice of u64 values.
/// Returns 0 for an empty slice.
pub(super) fn mean_u64(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let sum: u128 = values.iter().map(|v| u128::from(*v)).sum();
    (sum / values.len() as u128) as u64
}

/// Format nanoseconds as microseconds with 2 decimal places.
pub(super) fn format_duration_us(nanos: u64) -> String {
    let us = nanos as f64 / 1_000.0;
    format!("{us:.2} us")
}

/// Format a number with comma separators.
pub(super) fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}
