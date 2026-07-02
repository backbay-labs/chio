use super::super::*;
use super::should_retry_status;

impl TrustControlClient {
    pub(super) fn get_internal_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        term: Option<u64>,
    ) -> Result<T, CliError> {
        self.request_internal_get_json(path, path, term)
    }

    pub(super) fn get_internal_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &Q,
        term: Option<u64>,
    ) -> Result<T, CliError> {
        let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
            CliError::cli_other_error(format!("failed to encode trust control query: {error}"))
        })?;
        let url = if encoded_query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{encoded_query}")
        };
        self.request_internal_get_json(&url, path, term)
    }

    pub(super) fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, CliError> {
        self.request_json(
            |client, url, token| {
                client
                    .get(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call()
            },
            path,
        )
    }

    pub(super) fn public_get_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, CliError> {
        self.request_json_without_service_auth(|client, url| client.get(url).call(), path)
    }

    pub(super) fn public_get_text(&self, path: &str) -> Result<String, CliError> {
        self.request_text_without_service_auth(|client, url| client.get(url).call(), path)
    }

    pub(super) fn get_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &Q,
    ) -> Result<T, CliError> {
        let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
            CliError::cli_other_error(format!("failed to encode trust control query: {error}"))
        })?;
        let url = if encoded_query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{encoded_query}")
        };
        self.request_json(
            |client, base_url, token| {
                client
                    .get(&format!("{base_url}{url}"))
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call()
            },
            "",
        )
    }

    pub(crate) fn post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json(
            |client, url, token| {
                client
                    .post(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .send_json(json.clone())
            },
            path,
        )
    }

    pub(crate) fn post_internal_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
        term: Option<u64>,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_internal_post_json(path, json, term)
    }

    pub(super) fn public_post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json_without_service_auth(
            |client, url| client.post(url).send_json(json.clone()),
            path,
        )
    }

    pub(super) fn public_post_form<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &[(&str, &str)],
    ) -> Result<T, CliError> {
        self.request_json_without_service_auth(|client, url| client.post(url).send_form(body), path)
    }

    pub(super) fn bearer_post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        bearer_token: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json_with_bearer(
            |client, url| {
                client
                    .post(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {bearer_token}"))
                    .send_json(json.clone())
            },
            path,
        )
    }

    pub(super) fn put_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json(
            |client, url, token| {
                client
                    .put(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .send_json(json.clone())
            },
            path,
        )
    }

    pub(crate) fn delete_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, CliError> {
        self.request_json(
            |client, url, token| {
                client
                    .delete(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call()
            },
            path,
        )
    }

    fn request_internal_get_json<T>(
        &self,
        request_path: &str,
        auth_endpoint: &str,
        term: Option<u64>,
    ) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], request_path);
            let request = if self.cluster_peer_auth.is_some() {
                self.build_internal_get_request(&self.http, &url, auth_endpoint, term)?
            } else {
                self.http
                    .get(&url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {}", self.token))
            };
            match request.call() {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::cli_other_error(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(_, response)) => {
                    last_error = Some(response.into_string().unwrap_or_default());
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(format!("trust control service transport failed: {error}"));
                }
            }
        }
        Err(CliError::cli_other_error(last_error.unwrap_or_else(|| {
            "trust control service request failed".to_string()
        })))
    }

    fn request_internal_post_json<T>(
        &self,
        path: &str,
        body: Value,
        term: Option<u64>,
    ) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            let request = if self.cluster_peer_auth.is_some() {
                self.build_internal_post_request(&self.http, &url, path, term)?
            } else {
                self.http
                    .post(&url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {}", self.token))
            };
            match request.send_json(body.clone()) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::cli_other_error(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(_, response)) => {
                    last_error = Some(response.into_string().unwrap_or_default());
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(format!("trust control service transport failed: {error}"));
                }
            }
        }
        Err(CliError::cli_other_error(last_error.unwrap_or_else(|| {
            "trust control service request failed".to_string()
        })))
    }

    pub(crate) fn request_json<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&Agent, &str, &str) -> Result<ureq::Response, ureq::Error>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            match request(&self.http, &url, &self.token) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::cli_other_error(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(status, response)) if should_retry_status(status) => {
                    last_error = Some(CliError::cli_other_error(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Status(status, response)) => {
                    return Err(CliError::cli_other_error(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(CliError::cli_other_error(format!(
                        "trust control service transport failed: {error}"
                    )));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CliError::cli_other_error(
                "trust control service request failed with no endpoints".to_string(),
            )
        }))
    }

    fn request_json_without_service_auth<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&Agent, &str) -> Result<ureq::Response, ureq::Error>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            match request(&self.http, &url) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::cli_other_error(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(status, response)) if should_retry_status(status) => {
                    last_error = Some(CliError::cli_other_error(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Status(status, response)) => {
                    return Err(CliError::cli_other_error(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(CliError::cli_other_error(format!(
                        "trust control service transport failed: {error}"
                    )));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CliError::cli_other_error(
                "trust control service request failed with no endpoints".to_string(),
            )
        }))
    }

    pub(crate) fn request_text_without_service_auth<F>(
        &self,
        request: F,
        path: &str,
    ) -> Result<String, CliError>
    where
        F: Fn(&Agent, &str) -> Result<ureq::Response, ureq::Error>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            match request(&self.http, &url) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return response.into_string().map_err(|error| {
                        CliError::cli_other_error(format!(
                            "failed to decode trust control text response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(status, response)) if should_retry_status(status) => {
                    last_error = Some(CliError::cli_other_error(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Status(status, response)) => {
                    return Err(CliError::cli_other_error(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(CliError::cli_other_error(format!(
                        "trust control service transport failed: {error}"
                    )));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CliError::cli_other_error(
                "trust control service request failed with no endpoints".to_string(),
            )
        }))
    }

    fn request_json_with_bearer<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&Agent, &str) -> Result<ureq::Response, ureq::Error>,
    {
        self.request_json_without_service_auth(request, path)
    }

    pub(crate) fn endpoint_order(&self) -> Vec<usize> {
        let preferred = match self.preferred_index.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        };
        let total = self.endpoints.len();
        (0..total)
            .map(|offset| (preferred + offset) % total)
            .collect()
    }

    pub(crate) fn mark_preferred(&self, index: usize) {
        match self.preferred_index.lock() {
            Ok(mut guard) => *guard = index,
            Err(poisoned) => *poisoned.into_inner() = index,
        }
    }
}
