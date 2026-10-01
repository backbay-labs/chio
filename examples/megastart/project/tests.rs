include!("lib.rs");

#[test]
fn ordinary_windows() {
    assert_eq!(moving_average(&[2, 4, 8, 10], 2), Ok(vec![3, 6, 9]));
}
#[test]
fn zero_window_is_an_error() {
    assert!(moving_average(&[2, 4], 0).is_err());
    assert!(moving_average(&[], 0).is_err());
}
#[test]
fn incomplete_window_has_no_mean() {
    assert_eq!(moving_average(&[], 1), Ok(vec![]));
    assert_eq!(moving_average(&[4], 2), Ok(vec![]));
}
#[test]
fn wide_accumulator_preserves_large_means() {
    assert_eq!(moving_average(&[u64::MAX; 3], 2), Ok(vec![u64::MAX; 2]));
}
#[test]
fn rolling_update_matches_wide_reference() {
    let values = [0, u64::MAX, 7, u64::MAX - 1, 2, 10];
    for window in 1..=values.len() {
        let expected: Vec<u64> = values
            .windows(window)
            .map(|v| (v.iter().map(|&x| u128::from(x)).sum::<u128>() / window as u128) as u64)
            .collect();
        assert_eq!(moving_average(&values, window), Ok(expected));
    }
}
