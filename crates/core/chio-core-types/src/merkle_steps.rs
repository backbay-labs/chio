/// One level of an RFC 6962 inclusion-proof walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InclusionStep {
    /// Whether this level consumes an audit-path hash.
    pub consume_sibling: bool,
    /// Whether the consumed sibling is hashed before the current node.
    pub sibling_on_left: bool,
    /// Leaf index at the next tree level.
    pub next_index: u64,
    /// Node count at the next tree level.
    pub next_size: u64,
}

/// Classify one level of a carry-last-node RFC 6962 inclusion-proof walk.
#[must_use]
#[allow(clippy::manual_is_multiple_of)] // Matches the extraction-safe scalar mirror.
pub fn inclusion_step(index: u64, size: u64) -> InclusionStep {
    let sibling_on_left = index % 2 != 0;
    let right_sibling_exists = match index.checked_add(1) {
        Some(sibling) => sibling < size,
        None => false,
    };

    InclusionStep {
        consume_sibling: sibling_on_left || right_sibling_exists,
        sibling_on_left,
        next_index: index / 2,
        next_size: size / 2 + size % 2,
    }
}
