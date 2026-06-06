use crate::{HttpEgressContract, HttpEgressError, PreparedHttpEgressContract};
use reqwest::header::{
    HeaderMap, HeaderName, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, LOCATION,
    PROXY_AUTHORIZATION,
};
use reqwest::{Method, StatusCode, Url};
use serde::de::DeserializeOwned;
use std::error::Error;
use std::sync::Arc;

/// Response returned by [`send_with_contract`] after the full response body
/// has been read under the contract byte ceiling.
#[derive(Debug, Clone)]
pub struct ContractResponse {
    status: StatusCode,
    url: Url,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl ContractResponse {
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub async fn text(self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.body)
    }

    pub async fn json<T: DeserializeOwned>(self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

/// Wrap a `reqwest::Client::execute` call with [`HttpEgressContract`]
/// enforcement before each network hop and while reading the response body.
/// The supplied client must be built with [`client_builder_with_contract`],
/// which disables reqwest's automatic redirect following so this helper can
/// validate each `Location` target before issuing the next request.
pub async fn send_with_contract(
    contract: &HttpEgressContract,
    client: &reqwest::Client,
    request: reqwest::Request,
) -> Result<ContractResponse, HttpEgressError> {
    let prepared = contract.prepare()?;
    let mut request = request;
    let mut redirect_chain_len = 0_u8;

    loop {
        let request_url = request.url().clone();
        prepared.enforce_url_with_dns(request_url.as_str(), redirect_chain_len)?;
        let reusable_request = request.try_clone();
        let redirect_request = RedirectRequestParts {
            method: request.method().clone(),
            headers: request.headers().clone(),
            has_body: request.body().is_some(),
        };

        let response = client.execute(request).await.map_err(map_reqwest_error)?;
        if response.url() != &request_url {
            return Err(HttpEgressError::InvalidUrl(
                "reqwest client followed a redirect internally; build it with client_builder_with_contract"
                    .to_string(),
            ));
        }

        let status = response.status();
        if is_redirect_status(status) {
            if let Some(location) = response.headers().get(LOCATION).cloned() {
                if redirect_chain_len >= prepared.max_redirect_chain() {
                    return Err(HttpEgressError::RedirectLimitExceeded {
                        observed: redirect_chain_len.saturating_add(1),
                        max: prepared.max_redirect_chain(),
                    });
                }
                let location = location.to_str().map_err(|error| {
                    HttpEgressError::InvalidUrl(format!(
                        "invalid redirect Location header from {request_url}: {error}"
                    ))
                })?;
                let next_url = request_url.join(location).map_err(|error| {
                    HttpEgressError::InvalidUrl(format!(
                        "invalid redirect target `{location}` from {request_url}: {error}"
                    ))
                })?;
                let next_chain_len = redirect_chain_len.saturating_add(1);
                prepared.enforce_url_with_dns(next_url.as_str(), next_chain_len)?;
                let cross_origin = !same_origin(&request_url, &next_url);
                request = build_redirect_request(
                    client,
                    reusable_request,
                    redirect_request,
                    status,
                    next_url,
                    cross_origin,
                )?;
                redirect_chain_len = next_chain_len;
                continue;
            }
        }

        return collect_capped_response(&prepared, response).await;
    }
}

fn is_redirect_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

/// Builder for a contract-backed reqwest client. It deliberately exposes
/// only safe tuning knobs so callers cannot override the DNS resolver,
/// proxy policy, or redirect policy after contract protections are applied.
pub struct ContractClientBuilder {
    inner: reqwest::ClientBuilder,
}

impl ContractClientBuilder {
    #[must_use]
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    pub fn build(self) -> Result<reqwest::Client, reqwest::Error> {
        self.inner.build()
    }
}

/// Build a contract-backed reqwest client builder. [`send_with_contract`]
/// manually follows redirects after validating each hop and stripping
/// sensitive headers on cross-origin hops.
pub fn client_builder_with_contract(contract: &HttpEgressContract) -> ContractClientBuilder {
    ContractClientBuilder {
        inner: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .dns_resolver(Arc::new(ContractDnsResolver::new(contract.clone()))),
    }
}

#[derive(Clone)]
struct ContractDnsResolver {
    contract: HttpEgressContract,
}

impl ContractDnsResolver {
    fn new(contract: HttpEgressContract) -> Self {
        Self { contract }
    }
}

impl reqwest::dns::Resolve for ContractDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let contract = self.contract.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            if let Err(error) = contract.enforce_resolver_hostname(&host) {
                return Err(boxed_egress_error(error));
            }

            let lookup = match tokio::net::lookup_host((host.as_str(), 0)).await {
                Ok(lookup) => lookup,
                Err(error) => {
                    return Err(boxed_egress_error(HttpEgressError::DnsResolutionFailed {
                        host: host.clone(),
                        details: error.to_string(),
                    }));
                }
            };

            let mut addrs = Vec::new();
            for mut addr in lookup {
                if let Err(error) = contract.enforce_resolved_ip(&host, addr.ip()) {
                    return Err(boxed_egress_error(error));
                }
                addr.set_port(0);
                addrs.push(addr);
            }

            if addrs.is_empty() {
                return Err(boxed_egress_error(HttpEgressError::DnsResolutionFailed {
                    host: host.clone(),
                    details: "resolver returned no addresses".to_string(),
                }));
            }

            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn boxed_egress_error(error: HttpEgressError) -> Box<dyn Error + Send + Sync> {
    Box::new(error)
}

struct RedirectRequestParts {
    method: Method,
    headers: HeaderMap,
    has_body: bool,
}

fn build_redirect_request(
    client: &reqwest::Client,
    reusable_request: Option<reqwest::Request>,
    original: RedirectRequestParts,
    status: StatusCode,
    next_url: Url,
    cross_origin: bool,
) -> Result<reqwest::Request, HttpEgressError> {
    if cross_origin && (original.has_body || !is_idempotent_method(&original.method)) {
        return Err(HttpEgressError::InvalidUrl(format!(
            "cross-origin redirect method/body denied for {} {status} to {next_url}",
            original.method
        )));
    }

    let rewrite_to_get = status == StatusCode::SEE_OTHER && original.method != Method::HEAD
        || matches!(status, StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND)
            && original.method == Method::POST;
    if rewrite_to_get {
        let mut builder = client.request(Method::GET, next_url);
        for (name, value) in &original.headers {
            if should_drop_redirect_header(name, cross_origin, true) {
                continue;
            }
            builder = builder.header(name, value);
        }
        return builder.build().map_err(map_reqwest_error);
    }

    let mut request = reusable_request.ok_or_else(|| {
        HttpEgressError::InvalidUrl(
            "redirect requires a cloneable request body to replay safely".to_string(),
        )
    })?;
    *request.url_mut() = next_url;
    strip_redirect_headers(request.headers_mut(), cross_origin, false);
    Ok(request)
}

fn is_idempotent_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE
    )
}

fn should_drop_redirect_header(
    name: &HeaderName,
    cross_origin: bool,
    body_was_dropped: bool,
) -> bool {
    *name == HOST
        || body_was_dropped && (*name == CONTENT_LENGTH || *name == CONTENT_TYPE)
        || cross_origin && is_sensitive_request_header(name)
}

fn strip_redirect_headers(headers: &mut HeaderMap, cross_origin: bool, body_was_dropped: bool) {
    let names = headers.keys().cloned().collect::<Vec<_>>();
    for name in names {
        if should_drop_redirect_header(&name, cross_origin, body_was_dropped) {
            headers.remove(name);
        }
    }
}

fn is_sensitive_request_header(name: &HeaderName) -> bool {
    *name == AUTHORIZATION || *name == COOKIE || *name == PROXY_AUTHORIZATION
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str().map(str::to_ascii_lowercase)
            == right.host_str().map(str::to_ascii_lowercase)
        && left.port_or_known_default() == right.port_or_known_default()
}

async fn collect_capped_response(
    contract: &PreparedHttpEgressContract,
    mut response: reqwest::Response,
) -> Result<ContractResponse, HttpEgressError> {
    if let Some(content_length) = response.content_length() {
        contract.enforce_response_bytes(content_length)?;
    }

    let status = response.status();
    let url = response.url().clone();
    let headers = response.headers().clone();
    let mut observed = 0_u64;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
        observed =
            observed
                .checked_add(chunk.len() as u64)
                .ok_or(HttpEgressError::ResponseTooLarge {
                    observed: u64::MAX,
                    max: contract.max_response_bytes(),
                })?;
        contract.enforce_response_bytes(observed)?;
        body.extend_from_slice(&chunk);
    }

    Ok(ContractResponse {
        status,
        url,
        headers,
        body,
    })
}

fn map_reqwest_error(err: reqwest::Error) -> HttpEgressError {
    let kind = if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connect error"
    } else if err.is_request() {
        "request error"
    } else if err.is_body() {
        "body error"
    } else if err.is_decode() {
        "decode error"
    } else {
        "transport error"
    };
    HttpEgressError::InvalidUrl(format!("dispatch failed ({kind}): {err}"))
}
