use chio_tool_call_fabric::ProviderError;
use serde_json::Value;

/// Parsed SSE frame with original bytes retained for exact forwarding.
///
/// `done` is set when the frame's `data` payload equals the stream terminator
/// configured through [`SseParseOptions::with_done_sentinel`] (for example the
/// OpenAI `[DONE]` marker). Terminator frames carry `data: None` so callers do
/// not attempt to parse the sentinel string as JSON, while `raw` still holds the
/// original bytes for byte-exact forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseFrame {
    pub event: Option<String>,
    pub data: Option<Value>,
    pub raw: Vec<u8>,
    pub done: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownSseFieldPolicy {
    Ignore,
    Reject,
}

/// Parser configuration shared by every SSE-forwarding adapter.
///
/// The two boolean knobs cover the provider-specific SSE behaviors:
///
/// - `done_sentinel`: when set, a `data` payload equal to this string yields a
///   frame with `done = true` and `data = None` instead of being parsed as JSON.
/// - `cross_check_event_type`: when true, a frame that carries both an explicit
///   `event:` name and a JSON `type` field requires the two to agree, infers a
///   missing `event:` name from the `type` field, and rejects a data frame that
///   resolves to no event name at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseParseOptions {
    pub provider_label: &'static str,
    pub unknown_field_policy: UnknownSseFieldPolicy,
    pub done_sentinel: Option<&'static str>,
    pub cross_check_event_type: bool,
}

impl SseParseOptions {
    pub const fn ignoring_unknown(provider_label: &'static str) -> Self {
        Self {
            provider_label,
            unknown_field_policy: UnknownSseFieldPolicy::Ignore,
            done_sentinel: None,
            cross_check_event_type: false,
        }
    }

    pub const fn rejecting_unknown(provider_label: &'static str) -> Self {
        Self {
            provider_label,
            unknown_field_policy: UnknownSseFieldPolicy::Reject,
            done_sentinel: None,
            cross_check_event_type: false,
        }
    }

    /// Treat a `data` payload equal to `sentinel` as a stream terminator.
    pub const fn with_done_sentinel(mut self, sentinel: &'static str) -> Self {
        self.done_sentinel = Some(sentinel);
        self
    }

    /// Require an explicit `event:` name to match the JSON `type` field, infer a
    /// missing name from `type`, and reject data frames that resolve to no name.
    pub const fn with_event_type_cross_check(mut self) -> Self {
        self.cross_check_event_type = true;
        self
    }
}

struct SseLine<'a> {
    text: &'a str,
}

pub fn parse_sse_frames(
    raw: &[u8],
    options: SseParseOptions,
) -> Result<Vec<SseFrame>, ProviderError> {
    std::str::from_utf8(raw).map_err(|error| {
        ProviderError::Malformed(format!(
            "{} SSE bytes were not UTF-8: {error}",
            options.provider_label
        ))
    })?;

    let mut frames = Vec::new();
    let mut lines: Vec<SseLine<'_>> = Vec::new();
    let mut frame_raw: Vec<u8> = Vec::new();
    let mut offset = 0;

    while offset < raw.len() {
        let line_start = offset;
        let newline = raw[offset..].iter().position(|byte| *byte == b'\n');
        let (line_end, next_offset) = match newline {
            Some(relative) => {
                let line_end = offset + relative;
                (line_end, line_end + 1)
            }
            None => (raw.len(), raw.len()),
        };
        let raw_line = &raw[line_start..next_offset];
        let text_line = strip_line_ending(&raw[line_start..line_end]);
        let text = std::str::from_utf8(text_line).map_err(|error| {
            ProviderError::Malformed(format!(
                "{} SSE bytes were not UTF-8: {error}",
                options.provider_label
            ))
        })?;

        frame_raw.extend_from_slice(raw_line);
        if text.is_empty() {
            if !lines.is_empty() {
                frames.push(parse_sse_frame(
                    &lines,
                    std::mem::take(&mut frame_raw),
                    options,
                )?);
                lines.clear();
            } else {
                frame_raw.clear();
            }
        } else {
            lines.push(SseLine { text });
        }

        offset = next_offset;
    }

    if !lines.is_empty() {
        frames.push(parse_sse_frame(&lines, frame_raw, options)?);
    }

    Ok(frames)
}

fn strip_line_ending(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn parse_sse_frame(
    lines: &[SseLine<'_>],
    raw: Vec<u8>,
    options: SseParseOptions,
) -> Result<SseFrame, ProviderError> {
    let mut data_lines: Vec<String> = Vec::new();
    let mut event: Option<String> = None;

    for line in lines {
        let text = line.text;
        if text.starts_with(':') {
            continue;
        }
        let (field, value) = match text.split_once(':') {
            Some((field, value)) => (field, value),
            None => match options.unknown_field_policy {
                UnknownSseFieldPolicy::Ignore => (text, ""),
                UnknownSseFieldPolicy::Reject => {
                    return Err(ProviderError::Malformed(format!(
                        "{} SSE line `{text}` was missing `:`",
                        options.provider_label
                    )));
                }
            },
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "data" => data_lines.push(value.to_string()),
            "event" => event = Some(value.to_string()),
            "id" | "retry" => {}
            _ => match options.unknown_field_policy {
                UnknownSseFieldPolicy::Ignore => {}
                UnknownSseFieldPolicy::Reject => {
                    return Err(ProviderError::Malformed(format!(
                        "{} SSE field `{field}` is not supported",
                        options.provider_label
                    )));
                }
            },
        }
    }

    let data_text = data_lines.join("\n");
    if let Some(sentinel) = options.done_sentinel {
        if data_text == sentinel {
            return Ok(SseFrame {
                event,
                data: None,
                raw,
                done: true,
            });
        }
    }

    let data = if data_lines.is_empty() {
        None
    } else {
        Some(serde_json::from_str::<Value>(&data_text).map_err(|error| {
            ProviderError::Malformed(format!(
                "{} SSE data was not JSON: {error}",
                options.provider_label
            ))
        })?)
    };

    if options.cross_check_event_type {
        let inferred_event = data
            .as_ref()
            .and_then(|data| data.get("type"))
            .and_then(Value::as_str);
        if let (Some(existing), Some(data_type)) = (event.as_deref(), inferred_event) {
            if existing != data_type {
                return Err(ProviderError::Malformed(format!(
                    "{} SSE event `{existing}` did not match data type `{data_type}`",
                    options.provider_label
                )));
            }
        }
        if event.is_none() {
            event = inferred_event.map(ToString::to_string);
        }
        if data.is_some() && event.is_none() {
            return Err(ProviderError::Malformed(format!(
                "{} SSE data frame was missing event name",
                options.provider_label
            )));
        }
    }

    Ok(SseFrame {
        event,
        data,
        raw,
        done: false,
    })
}
