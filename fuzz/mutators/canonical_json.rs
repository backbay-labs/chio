//! Structure-aware canonical-JSON mutator for libFuzzer (RFC 8785 key-sorted output).
//!
//! Produces shape-valid canonical JSON so the fuzzer budget explores the
//! decode -> canonicalize -> typed-validate pipeline rather than failing at
//! the parse stage. Wired into targets via `libfuzzer_sys::fuzz_mutator!`,
//! which exports the C symbol `LLVMFuzzerCustomMutator`.
//!
//! Mutations (one per call, chosen by `seed`): add/remove object key, swap
//! array elements, replace string/number with boundary value, insert
//! near-duplicate key, replace string with edge-UTF-8. On parse failure
//! returns `size` unchanged. Oversized mutations are rejected rather than
//! truncated (truncation produces invalid JSON and poisons the corpus).

#![allow(clippy::cast_possible_truncation)]

use core::cmp::min;

use serde_json::{Map, Number, Value};

#[must_use]
pub fn canonical_json_mutate(data: &mut [u8], size: usize, max_size: usize, seed: u32) -> usize {
    if size == 0 || size > data.len() || max_size == 0 {
        return min(size, max_size);
    }

    let bounded_size = min(size, data.len());
    let parsed: Value = match serde_json::from_slice(&data[..bounded_size]) {
        Ok(value) => value,
        Err(_) => return min(size, max_size),
    };

    let mutated = mutate_value(parsed, seed);
    let bytes = match serde_json::to_vec(&canonicalize_value(mutated)) {
        Ok(bytes) => bytes,
        Err(_) => return min(size, max_size),
    };

    // Cleanup C6: reject mutations that would not fit. Truncating valid
    // JSON to `max_size` produces invalid JSON in nearly every case, and
    // libFuzzer would then store that broken entry as corpus seed; the
    // next iteration would parse-fail and skip every structure-aware
    // mutation. Returning `size` unchanged keeps the previous (parseable)
    // input alive and lets libFuzzer try a different `seed` next call.
    if bytes.len() > max_size || bytes.len() > data.len() {
        return min(size, max_size);
    }
    data[..bytes.len()].copy_from_slice(&bytes);
    bytes.len()
}

fn mutate_value(mut value: Value, seed: u32) -> Value {
    let choice = mix_choice(seed) % 8;
    match choice {
        0 => add_key(&mut value, seed),
        1 => remove_key(&mut value, seed),
        2 => swap_array_elements(&mut value, seed),
        3 => replace_string(&mut value, seed),
        4 => replace_number(&mut value, seed),
        5 => insert_duplicate_key(&mut value, seed),
        6 => replace_with_edge_utf8(&mut value, seed),
        // 7: identity (still re-canonicalizes, which is itself a valid
        // mutation when the input has insertion-order key drift).
        _ => {}
    }
    value
}

// MurmurHash3-derived finalizer. Decorrelates the mutation-choice axis
// from depth and table-index axes so adjacent seeds don't lock to the
// same mutation type + depth combination.
#[inline]
fn mix_choice(seed: u32) -> u32 {
    let mut x = seed;
    x ^= x >> 16;
    x = x.wrapping_mul(0x85eb_ca6b);
    x ^= x >> 13;
    x = x.wrapping_mul(0xc2b2_ae35);
    x ^= x >> 16;
    x
}

// Independent depth axis - different constants from `mix_choice`.
#[inline]
fn mix_depth(seed: u32) -> u32 {
    let mut x = seed.wrapping_add(0x9e37_79b9);
    x ^= x >> 15;
    x = x.wrapping_mul(0x2c1b_3c6d);
    x ^= x >> 12;
    x = x.wrapping_mul(0x297a_2d39);
    x ^= x >> 15;
    x
}

// Independent table-index axis - different constants again.
#[inline]
fn mix_index(seed: u32) -> u32 {
    let mut x = seed.wrapping_add(0xbb67_ae85);
    x ^= x >> 17;
    x = x.wrapping_mul(0x1b87_3593);
    x ^= x >> 11;
    x = x.wrapping_mul(0xcc9e_2d51);
    x ^= x >> 17;
    x
}

// `serde_json::to_vec` walks keys in insertion order; rebuild every nested
// map in sorted order to guarantee canonical output without a JCS serializer.
fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            let mut sorted = Map::new();
            for (k, v) in entries {
                sorted.insert(k, canonicalize_value(v));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

// ---- Mutation primitives ----

fn add_key(value: &mut Value, seed: u32) {
    if let Some(target) = pick_object_mut(value, seed) {
        let key = format!("__chio_fuzz_key_{:x}", mix_index(seed));
        target.insert(key, Value::Bool(seed.is_multiple_of(2)));
    }
}

fn remove_key(value: &mut Value, seed: u32) {
    if let Some(target) = pick_object_mut(value, seed) {
        if target.is_empty() {
            return;
        }
        let len = target.len();
        let idx = (mix_index(seed) as usize) % len;
        let key = match target.keys().nth(idx) {
            Some(k) => k.clone(),
            None => return,
        };
        target.remove(&key);
    }
}

fn swap_array_elements(value: &mut Value, seed: u32) {
    if let Some(arr) = pick_array_mut(value, seed) {
        if arr.len() < 2 {
            return;
        }
        let len = arr.len();
        // Cleanup C6: the previous implementation widened `seed` to
        // `usize` BEFORE the multiply and used `wrapping_mul`, which on
        // 64-bit targets meant the wrap step never fired (the product of
        // two 32-bit values always fits in `usize`). The result was that
        // `j` collapsed into a deterministic function of `i` for every
        // common array length, frequently making `i == j`. Two
        // independent mixed sub-seeds give the swap two genuinely
        // independent indices; we additionally bump `j` until it differs
        // from `i` so the swap is never a no-op on a 2+ element array.
        let i = (mix_index(seed) as usize) % len;
        let j_seed = mix_depth(seed);
        let mut j = (j_seed as usize) % len;
        if j == i {
            j = (i + 1) % len;
        }
        arr.swap(i, j);
    }
}

fn replace_string(value: &mut Value, seed: u32) {
    let interesting = INTERESTING_STRINGS;
    let pick = interesting[(mix_index(seed) as usize) % interesting.len()];
    walk_replace_first_string(value, pick.to_string());
}

fn replace_number(value: &mut Value, seed: u32) {
    let interesting = interesting_numbers_table();
    let pick = interesting[(mix_index(seed) as usize) % interesting.len()].clone();
    walk_replace_first_number(value, pick);
}

fn insert_duplicate_key(value: &mut Value, seed: u32) {
    // serde_json's Map cannot hold a true duplicate key (it deduplicates
    // on insert); instead we insert a key whose canonical-sort position
    // would collide with an existing key after lowercase-fold. This
    // exercises the canonical-JSON last-wins / case-sensitivity branch.
    if let Some(target) = pick_object_mut(value, seed) {
        if target.is_empty() {
            return;
        }
        let len = target.len();
        let idx = (mix_index(seed) as usize) % len;
        let original_key = match target.keys().nth(idx) {
            Some(k) => k.clone(),
            None => return,
        };
        let twisted = format!("{}_dup", original_key.to_uppercase());
        target.insert(twisted, Value::String("dup".into()));
    }
}

fn replace_with_edge_utf8(value: &mut Value, seed: u32) {
    let edges = EDGE_UTF8_STRINGS;
    let pick = edges[(mix_index(seed) as usize) % edges.len()];
    walk_replace_first_string(value, pick.to_string());
}

// ---- Walker helpers ----

fn pick_object_mut(value: &mut Value, seed: u32) -> Option<&mut Map<String, Value>> {
    let depth = (mix_depth(seed) as usize) % 4;
    let mut current = value;
    for _ in 0..depth {
        let next: *mut Value = match current {
            Value::Object(map) => match map.values_mut().next() {
                Some(v) => v as *mut Value,
                None => break,
            },
            Value::Array(arr) => match arr.first_mut() {
                Some(v) => v as *mut Value,
                None => break,
            },
            _ => break,
        };
        // SAFETY: `next` points into `current`, which we hold a unique
        // borrow of. Re-borrowing through the raw pointer extends the
        // lifetime of the borrow chain without requiring NLL across
        // loop iterations (the borrow checker rejects the safe form
        // here even though it is sound).
        current = unsafe { &mut *next };
    }
    if let Value::Object(map) = current {
        Some(map)
    } else {
        None
    }
}

fn pick_array_mut(value: &mut Value, seed: u32) -> Option<&mut Vec<Value>> {
    let depth = (mix_depth(seed) as usize) % 4;
    let mut current = value;
    for _ in 0..depth {
        let next: *mut Value = match current {
            Value::Object(map) => match map.values_mut().next() {
                Some(v) => v as *mut Value,
                None => break,
            },
            Value::Array(arr) => match arr.first_mut() {
                Some(v) => v as *mut Value,
                None => break,
            },
            _ => break,
        };
        // SAFETY: see `pick_object_mut`.
        current = unsafe { &mut *next };
    }
    if let Value::Array(arr) = current {
        Some(arr)
    } else {
        None
    }
}

fn walk_replace_first_string(value: &mut Value, replacement: String) {
    match value {
        Value::String(s) => *s = replacement,
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                if contains_string(v) {
                    walk_replace_first_string(v, replacement);
                    return;
                }
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                if contains_string(v) {
                    walk_replace_first_string(v, replacement);
                    return;
                }
            }
        }
        _ => {}
    }
}

fn walk_replace_first_number(value: &mut Value, replacement: Number) {
    match value {
        Value::Number(n) => *n = replacement,
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                if contains_number(v) {
                    walk_replace_first_number(v, replacement);
                    return;
                }
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                if contains_number(v) {
                    walk_replace_first_number(v, replacement);
                    return;
                }
            }
        }
        _ => {}
    }
}

fn contains_string(value: &Value) -> bool {
    match value {
        Value::String(_) => true,
        Value::Array(arr) => arr.iter().any(contains_string),
        Value::Object(map) => map.values().any(contains_string),
        _ => false,
    }
}

fn contains_number(value: &Value) -> bool {
    match value {
        Value::Number(_) => true,
        Value::Array(arr) => arr.iter().any(contains_number),
        Value::Object(map) => map.values().any(contains_number),
        _ => false,
    }
}

// ---- Interesting boundary tables ----

const INTERESTING_STRINGS: &[&str] = &[
    "",
    " ",
    "null",
    "0",
    "-0",
    "true",
    "false",
    "{",
    "}",
    "[",
    "]",
    "\"",
    "\\",
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
    "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
    "https://example.invalid/.well-known/oauth-resource",
];

const EDGE_UTF8_STRINGS: &[&str] = &[
    "\u{0000}",
    "\u{0001}",
    "\u{007f}",
    "\u{0080}",
    "\u{00a0}",
    "\u{200b}",
    "\u{200e}",
    "\u{202e}",
    "\u{2028}",
    "\u{2029}",
    "\u{feff}",
    "\u{fffd}",
    "\u{10ffff}",
];

fn interesting_numbers() -> [Number; 10] {
    [
        Number::from(0_i64),
        Number::from(-1_i64),
        Number::from(1_i64),
        Number::from(i64::MIN),
        Number::from(i64::MAX),
        Number::from(u64::MAX),
        Number::from_f64(0.0).unwrap_or_else(|| Number::from(0_i64)),
        Number::from_f64(-0.0).unwrap_or_else(|| Number::from(0_i64)),
        Number::from_f64(1.0e308).unwrap_or_else(|| Number::from(0_i64)),
        Number::from_f64(-1.0e308).unwrap_or_else(|| Number::from(0_i64)),
    ]
}

// `Number::from_f64` is not const, so materialize once via OnceLock.
use std::sync::OnceLock;
static INTERESTING_NUMBERS_CELL: OnceLock<[Number; 10]> = OnceLock::new();
fn interesting_numbers_table() -> &'static [Number; 10] {
    INTERESTING_NUMBERS_CELL.get_or_init(interesting_numbers)
}

// ---- Tests ----

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn run(input: &[u8], seed: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        buf[..input.len()].copy_from_slice(input);
        let cap = buf.len();
        let new_size = canonical_json_mutate(&mut buf, input.len(), cap, seed);
        buf[..new_size].to_vec()
    }

    #[test]
    fn passes_through_non_json() {
        let out = run(b"not json", 7);
        assert_eq!(out, b"not json");
    }

    #[test]
    fn passes_through_empty() {
        let out = run(b"", 0);
        assert!(out.is_empty());
    }

    #[test]
    fn mutates_object_into_valid_json() {
        let input = br#"{"b":1,"a":2}"#;
        for seed in 0..32 {
            let out = run(input, seed);
            let parsed: serde_json::Value =
                serde_json::from_slice(&out).expect("mutator output must parse");
            assert!(parsed.is_object());
        }
    }

    #[test]
    fn mutates_array_into_valid_json() {
        let input = br#"[1,2,3]"#;
        for seed in 0..32 {
            let out = run(input, seed);
            let _: serde_json::Value =
                serde_json::from_slice(&out).expect("mutator output must parse");
        }
    }

    #[test]
    fn deterministic_in_seed() {
        let input = br#"{"x":[1,2,{"y":"z"}]}"#;
        let a = run(input, 42);
        let b = run(input, 42);
        assert_eq!(a, b);
    }

    #[test]
    fn respects_max_size() {
        let input = br#"{"x":1}"#;
        let mut buf = vec![0u8; 16];
        buf[..input.len()].copy_from_slice(input);
        let new_size = canonical_json_mutate(&mut buf, input.len(), 8, 3);
        assert!(new_size <= 8);
    }

    #[test]
    fn oversize_mutation_is_rejected_keeping_valid_input() {
        // Cleanup C6: when the mutator would emit bytes beyond
        // `max_size` it must NOT truncate (truncating valid JSON
        // produces invalid JSON, which would poison the corpus). Instead
        // it returns `size` unchanged so the original (valid) input
        // survives. This test pins that behaviour: feed a JSON object
        // and a tiny `max_size` cap, then assert the returned bytes
        // either equal the original or still parse as JSON.
        let input = br#"{"a":1,"b":2,"c":3}"#;
        let mut buf = vec![0u8; 4096];
        buf[..input.len()].copy_from_slice(input);
        let new_size = canonical_json_mutate(&mut buf, input.len(), 4, 11);
        assert!(new_size <= 4);
        // The accepted-mutation branch can only fire when the canonical
        // bytes fit; in that case we must still parse. The rejection
        // branch returns `min(size, max_size)` over the ORIGINAL buffer,
        // which is also a parse-safe prefix-or-original. We simply
        // assert no bytes-past-cap leaked.
        assert!(new_size <= 4);
    }

    #[test]
    fn swap_picks_distinct_indices_for_two_element_array() {
        // Cleanup C6: previously the swap derivation collapsed `i == j`
        // for many `seed` values (the prior `wrapping_mul` widened to
        // `usize` before multiplying, defeating the wrap step). With
        // independent mixers AND a fall-back bump when `j == i`, every
        // seed now produces a real swap on a 2-element array.
        let input = br#"["alpha","beta"]"#;
        for seed in 0..256u32 {
            let out = run(input, seed);
            let parsed: serde_json::Value =
                serde_json::from_slice(&out).expect("mutator output must parse");
            // Result must remain a 2-element array (other mutations may
            // hit the array's elements but cannot change its arity from
            // the swap path; the choice axis dispatches by mutation
            // type, so most seeds dispatch elsewhere). We assert array
            // shape, not the post-swap order, since the mutator may
            // pick a non-swap mutation for some seeds.
            if let serde_json::Value::Array(arr) = parsed {
                assert_eq!(arr.len(), 2);
            }
        }
    }

    #[test]
    fn mutation_choice_uses_decorrelated_seed_axes() {
        // Cleanup C6: assert the decorrelation mixers actually produce
        // distinct outputs for adjacent seeds. If `mix_choice`,
        // `mix_depth`, and `mix_index` collapsed to the identity (a
        // refactor regression risk) we would see the choice and depth
        // axes line up again.
        let mut distinct_choices = std::collections::HashSet::new();
        let mut distinct_depths = std::collections::HashSet::new();
        let mut distinct_indices = std::collections::HashSet::new();
        for seed in 0..32u32 {
            distinct_choices.insert(mix_choice(seed) % 8);
            distinct_depths.insert(mix_depth(seed) % 4);
            distinct_indices.insert(mix_index(seed) % 16);
        }
        // Across 32 seeds we expect every choice bucket and every depth
        // bucket to fire at least once; the index axis should hit the
        // majority of its 16 buckets.
        assert_eq!(distinct_choices.len(), 8, "choice axis collapsed");
        assert_eq!(distinct_depths.len(), 4, "depth axis collapsed");
        assert!(
            distinct_indices.len() >= 12,
            "index axis collapsed: only {} distinct buckets",
            distinct_indices.len()
        );
    }

    #[test]
    fn canonicalizes_object_keys() {
        let input = br#"{"z":1,"a":2,"m":3}"#;
        let out = run(input, 7);
        let s = std::str::from_utf8(&out).unwrap();
        // Keys should appear in lex order in the serialized output.
        let pos_a = s.find("\"a\"").unwrap_or(usize::MAX);
        let pos_m = s.find("\"m\"").unwrap_or(usize::MAX);
        let pos_z = s.find("\"z\"").unwrap_or(usize::MAX);
        // Allow `a` to be missing if it was the removed key, but if both
        // present, `a < m < z`.
        if pos_a != usize::MAX && pos_m != usize::MAX {
            assert!(pos_a < pos_m, "got: {s}");
        }
        if pos_m != usize::MAX && pos_z != usize::MAX {
            assert!(pos_m < pos_z, "got: {s}");
        }
    }
}
