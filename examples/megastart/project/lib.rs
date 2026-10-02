/// Means for complete windows; accumulation must not overflow for u64 inputs.
pub fn moving_average(values: &[u64], window: usize) -> Result<Vec<u64>, &'static str> {
    if window > values.len() {
        return Ok(Vec::new());
    }
    let mut sum: u64 = values[..window].iter().copied().sum();
    let mut output = Vec::with_capacity(values.len() - window + 1);
    output.push((sum / window as u64) as u64);
    for index in window..values.len() {
        sum -= values[index - window] as u64;
        sum += values[index] as u64;
        output.push((sum / window as u64) as u64);
    }
    Ok(output)
}
