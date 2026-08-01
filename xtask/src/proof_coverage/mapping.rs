use super::*;

pub(super) fn parse_mapping(input: &str) -> MappingParse {
    let mut parsed = MappingParse::default();
    let mut section = String::new();
    let mut headers: Option<Vec<String>> = None;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if let Some(heading) = line.strip_prefix("## ") {
            section = heading.trim().to_string();
            headers = None;
            continue;
        }
        if !(line.starts_with('|') && line.ends_with('|')) {
            if !line.is_empty() {
                headers = None;
            }
            continue;
        }
        let cells = markdown_cells(line);
        if headers.is_none() {
            let looks_like_property_header = cells.iter().any(|cell| {
                cell == "Property"
                    || cell == "Source"
                    || cell.starts_with("Source ")
                    || cell == "Rust path constrained"
            });
            if looks_like_property_header {
                let mut missing = Vec::new();
                if !cells.iter().any(|cell| cell == "Property") {
                    missing.push("Property");
                }
                if !cells
                    .iter()
                    .any(|cell| cell == "Source" || cell.starts_with("Source "))
                {
                    missing.push("Source");
                }
                if !cells.iter().any(|cell| cell == "Rust path constrained") {
                    missing.push("Rust path constrained");
                }
                if !missing.is_empty() {
                    parsed.warnings.push(format!(
                        "line {line_number}: property table missing required columns: {}",
                        missing.join(", ")
                    ));
                    continue;
                }
                headers = Some(cells);
            }
            continue;
        }
        let Some(table_headers) = headers.as_ref() else {
            continue;
        };
        if separator_cells(&cells) {
            continue;
        }
        if cells.len() != table_headers.len() {
            parsed.warnings.push(format!(
                "line {line_number}: expected {} cells, found {}",
                table_headers.len(),
                cells.len()
            ));
            continue;
        }
        let Some(property_index) = table_headers.iter().position(|cell| cell == "Property") else {
            continue;
        };
        let Some(source_index) = table_headers
            .iter()
            .position(|cell| cell == "Source" || cell.starts_with("Source "))
        else {
            continue;
        };
        let Some(rust_index) = table_headers
            .iter()
            .position(|cell| cell == "Rust path constrained")
        else {
            continue;
        };
        parsed.rows.push(MappingRow {
            section: section.clone(),
            property: strip_code_span(&cells[property_index]),
            source: strip_code_span(&cells[source_index]),
            rust_paths: cells[rust_index].clone(),
        });
    }
    parsed
}

pub(super) fn validate_kani_crates(
    harnesses: &[KaniHarness],
    workspace_members: &BTreeSet<String>,
) -> Result<(), String> {
    for harness in harnesses {
        if !workspace_members.contains(&harness.crate_name) {
            return Err(format!(
                "Kani harness {} names non-workspace crate {}",
                harness.harness, harness.crate_name
            ));
        }
    }
    Ok(())
}
