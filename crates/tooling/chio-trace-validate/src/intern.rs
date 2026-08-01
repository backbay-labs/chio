use std::collections::BTreeMap;

use crate::TraceError;

const MAX_INTERNED_VALUES: usize = 64;

#[derive(Debug, Default)]
pub(crate) struct Interner {
    values: BTreeMap<String, u32>,
}

impl Interner {
    pub(crate) fn intern(&mut self, value: &str, label: &str) -> Result<u32, TraceError> {
        if let Some(index) = self.values.get(value) {
            return Ok(*index);
        }
        if self.values.len() >= MAX_INTERNED_VALUES {
            return Err(TraceError::InvalidInput(format!(
                "trace exceeds {MAX_INTERNED_VALUES} distinct {label} values"
            )));
        }
        let index = u32::try_from(self.values.len() + 1)
            .map_err(|_| TraceError::InvalidInput(format!("{label} index overflow")))?;
        self.values.insert(value.to_string(), index);
        Ok(index)
    }

    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }
}
