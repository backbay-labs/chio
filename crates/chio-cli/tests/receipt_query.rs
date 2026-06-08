#![allow(clippy::expect_used, clippy::too_many_arguments, clippy::unwrap_used)]

mod support;

use support::receipt_query::*;

macro_rules! skip_when_loopback_denied {
    ($test_name:ident) => {
        if chio_test_support::loopback::skip_when_loopback_bind_denied(stringify!($test_name)) {
            return;
        }
    };
}

#[test]
fn test_receipt_query_no_filters() {
    skip_when_loopback_denied!(test_receipt_query_no_filters);
    let setup = setup_with_receipts("chio-rq-no-filters");

    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let total_count = body["totalCount"].as_u64().expect("totalCount is u64");
    let receipts = body["receipts"].as_array().expect("receipts is array");

    assert_eq!(
        total_count, 5,
        "all 5 inserted receipts should be in totalCount"
    );
    assert_eq!(
        receipts.len(),
        5,
        "all 5 receipts should be returned with default limit"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_receipt_query_requires_auth() {
    skip_when_loopback_denied!(test_receipt_query_requires_auth);
    let setup = setup_with_receipts("chio-rq-auth");

    // No Authorization header.
    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .send()
        .expect("send request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "request without auth should return 401"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_api_routes_not_shadowed_by_spa() {
    skip_when_loopback_denied!(test_api_routes_not_shadowed_by_spa);
    let setup = setup_with_receipts("chio-api-priority");

    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send API request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "API should return 200"
    );

    // The Content-Type must be application/json, not text/html.
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("application/json"),
        "API response Content-Type should be application/json, got: {content_type}"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}
