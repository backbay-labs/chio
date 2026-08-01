#[allow(warnings)]
mod bindings;

use bindings::{GuardRequest, Guest, Verdict};

struct Component;

impl Guest for Component {
    fn evaluate(request: GuardRequest) -> Verdict {
        if request.tool_name == "smith-allow" {
            Verdict::Allow
        } else {
            Verdict::Deny("smith-selected-deny".to_string())
        }
    }
}

bindings::export!(Component with_types_in bindings);
