use super::*;

pub(crate) fn cmd_passport_policy_create(
    args: PassportPolicyCreateArgs<'_>,
) -> Result<(), CliError> {
    let PassportPolicyCreateArgs {
        output,
        policy_id,
        verifier,
        signing_seed_file,
        policy_path,
        expires_at,
        verifier_policies_file,
        json_output,
        control_url,
        control_token,
    } = args;
    let now = unix_now();
    let keypair = load_or_create_authority_keypair(signing_seed_file)?;
    let policy = load_passport_verifier_policy(policy_path)?;
    let document = create_signed_passport_verifier_policy(
        &keypair, policy_id, verifier, now, expires_at, policy,
    )?;

    ensure_parent_dir(output)?;
    fs::write(output, serde_json::to_vec_pretty(&document)?)?;

    let registration = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .upsert_verifier_policy(policy_id, &document)?;
        Some(url.to_string())
    } else if let Some(path) = verifier_policies_file {
        let mut registry = load_verifier_policy_registry_for_admin(path)?;
        registry.upsert(document.clone())?;
        registry.save(path)?;
        Some(path.display().to_string())
    } else {
        None
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&document)?);
    } else {
        println!("verifier policy created");
        println!("output:            {}", output.display());
        println!("policy_id:         {}", document.body.policy_id);
        println!("verifier:          {}", document.body.verifier);
        println!(
            "signer_public_key: {}",
            document.body.signer_public_key.to_hex()
        );
        println!("created_at:        {}", document.body.created_at);
        println!("expires_at:        {}", document.body.expires_at);
        if let Some(registration) = registration.as_deref() {
            println!("registered_in:     {registration}");
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_policy_verify(
    input: &Path,
    at: Option<u64>,
    json_output: bool,
) -> Result<(), CliError> {
    let document = load_signed_passport_verifier_policy(input)?;
    verify_signed_passport_verifier_policy(&document)
        .map_err(|error| CliError::policy_error(error.to_string()))?;
    ensure_signed_passport_verifier_policy_active(&document, at.unwrap_or_else(unix_now))
        .map_err(|error| CliError::policy_error(error.to_string()))?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&document)?);
    } else {
        println!("verifier policy verified");
        println!("policy_id:         {}", document.body.policy_id);
        println!("verifier:          {}", document.body.verifier);
        println!(
            "signer_public_key: {}",
            document.body.signer_public_key.to_hex()
        );
        println!("created_at:        {}", document.body.created_at);
        println!("expires_at:        {}", document.body.expires_at);
    }
    Ok(())
}

pub(crate) fn cmd_passport_policy_list(
    json_output: bool,
    verifier_policies_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .list_verifier_policies()?
    } else {
        let path = require_verifier_policy_registry_path(verifier_policies_file)?;
        let registry = load_verifier_policy_registry_for_admin(path)?;
        VerifierPolicyListResponse {
            configured: true,
            count: registry.policies.len(),
            policies: registry.policies.into_values().collect(),
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("configured: {}", response.configured);
        println!("count:      {}", response.count);
        for document in response.policies {
            println!(
                "- {} ({}) expires_at={}",
                document.body.policy_id, document.body.verifier, document.body.expires_at
            );
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_policy_get(
    policy_id: &str,
    json_output: bool,
    verifier_policies_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let document = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .get_verifier_policy(policy_id)?
    } else {
        let path = require_verifier_policy_registry_path(verifier_policies_file)?;
        let registry = load_verifier_policy_registry_for_admin(path)?;
        registry.get(policy_id).cloned().ok_or_else(|| {
            CliError::policy_error(format!("verifier policy `{policy_id}` was not found"))
        })?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&document)?);
    } else {
        println!("policy_id:         {}", document.body.policy_id);
        println!("verifier:          {}", document.body.verifier);
        println!(
            "signer_public_key: {}",
            document.body.signer_public_key.to_hex()
        );
        println!("created_at:        {}", document.body.created_at);
        println!("expires_at:        {}", document.body.expires_at);
    }
    Ok(())
}

pub(crate) fn cmd_passport_policy_upsert(
    input: &Path,
    json_output: bool,
    verifier_policies_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let document = load_signed_passport_verifier_policy(input)?;
    verify_signed_passport_verifier_policy(&document)
        .map_err(|error| CliError::policy_error(error.to_string()))?;
    let saved = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .upsert_verifier_policy(&document.body.policy_id, &document)?
    } else {
        let path = require_verifier_policy_registry_path(verifier_policies_file)?;
        let mut registry = load_verifier_policy_registry_for_admin(path)?;
        registry.upsert(document.clone())?;
        registry.save(path)?;
        document
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&saved)?);
    } else {
        println!("verifier policy upserted");
        println!("policy_id:  {}", saved.body.policy_id);
        println!("verifier:   {}", saved.body.verifier);
        println!("expires_at: {}", saved.body.expires_at);
    }
    Ok(())
}

pub(crate) fn cmd_passport_policy_delete(
    policy_id: &str,
    json_output: bool,
    verifier_policies_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (deleted, configured) = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        let response = crate::trust_control::service_runtime::client::build_client(url, token)?
            .delete_verifier_policy(policy_id)?;
        (response.deleted, true)
    } else {
        let path = require_verifier_policy_registry_path(verifier_policies_file)?;
        let mut registry = load_verifier_policy_registry_for_admin(path)?;
        let deleted = registry.remove(policy_id);
        registry.save(path)?;
        (deleted, true)
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "configured": configured,
                "policyId": policy_id,
                "deleted": deleted,
            }))?
        );
    } else {
        println!("configured: {configured}");
        println!("policy_id:  {policy_id}");
        println!("deleted:    {deleted}");
    }
    Ok(())
}

pub(crate) fn cmd_passport_challenge_create(
    args: PassportChallengeCreateArgs<'_>,
) -> Result<(), CliError> {
    let PassportChallengeCreateArgs {
        output,
        verifier,
        ttl_secs,
        issuers,
        max_credentials,
        policy_path,
        policy_id,
        verifier_policies_file,
        verifier_challenge_db,
        json_output,
        control_url,
        control_token,
    } = args;
    let now = unix_now();
    if policy_path.is_some() && policy_id.is_some() {
        return Err(CliError::cli_other_error(
            "challenge creation accepts either --policy or --policy-id, not both".to_string(),
        ));
    }
    let challenge_response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .create_passport_challenge(&CreatePassportChallengeRequest {
                verifier: verifier.to_string(),
                ttl_seconds: ttl_secs,
                issuers: issuers.to_vec(),
                max_credentials,
                policy_id: policy_id.map(str::to_string),
                policy: policy_path.map(load_passport_verifier_policy).transpose()?,
            })?
    } else {
        let (policy_ref, policy, policy_verifier) = if let Some(policy_id) = policy_id {
            let path = require_verifier_policy_registry_path(verifier_policies_file)?;
            let registry = load_verifier_policy_registry_for_admin(path)?;
            let document = registry.active_policy(policy_id, now)?;
            (
                Some(PassportVerifierPolicyReference {
                    policy_id: document.body.policy_id.clone(),
                }),
                None,
                document.body.verifier.clone(),
            )
        } else {
            (
                None,
                policy_path.map(load_passport_verifier_policy).transpose()?,
                verifier.to_string(),
            )
        };
        if policy_ref.is_some() && policy_verifier != verifier {
            return Err(CliError::policy_error(
                "stored verifier policy verifier must match --verifier".to_string(),
            ));
        }
        let challenge = create_passport_presentation_challenge_with_reference(
            chio_credentials::PassportPresentationChallengeArgs {
                verifier: verifier.to_string(),
                challenge_id: Some(Keypair::generate().public_key().to_hex()),
                nonce: Keypair::generate().public_key().to_hex(),
                issued_at: now,
                expires_at: now.saturating_add(ttl_secs),
                options: PassportPresentationOptions {
                    issuer_allowlist: issuers.iter().cloned().collect::<BTreeSet<_>>(),
                    max_credentials,
                },
                policy_ref,
                policy,
            },
        )?;
        if let Some(path) = verifier_challenge_db {
            PassportVerifierChallengeStore::open(path)?.register(&challenge)?;
        }
        CreatePassportChallengeResponse {
            challenge,
            transport: None,
        }
    };
    let challenge = &challenge_response.challenge;

    ensure_parent_dir(output)?;
    fs::write(output, serde_json::to_vec_pretty(&challenge)?)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output": output.display().to_string(),
                "verifier": challenge.verifier,
                "challengeId": challenge.challenge_id,
                "nonce": challenge.nonce,
                "expiresAt": challenge.expires_at,
                "policyId": challenge.policy_ref.as_ref().map(|reference| reference.policy_id.clone()),
                "policyEmbedded": challenge.policy.is_some(),
                "transport": challenge_response.transport,
            }))?
        );
    } else {
        println!("wrote challenge to {}", output.display());
        println!("verifier:        {}", challenge.verifier);
        if let Some(challenge_id) = challenge.challenge_id.as_deref() {
            println!("challenge_id:    {challenge_id}");
        }
        println!("nonce:           {}", challenge.nonce);
        println!("expires_at:      {}", challenge.expires_at);
        if let Some(policy_id) = challenge
            .policy_ref
            .as_ref()
            .map(|reference| reference.policy_id.as_str())
        {
            println!("policy_id:       {policy_id}");
        }
        println!("policy_embedded: {}", challenge.policy.is_some());
        if let Some(transport) = challenge_response.transport.as_ref() {
            println!("challenge_url:   {}", transport.challenge_url);
            println!("submit_url:      {}", transport.submit_url);
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_challenge_respond(
    input: &Path,
    challenge_path: Option<&Path>,
    challenge_url: Option<&str>,
    holder_seed_file: &Path,
    output: &Path,
    at: Option<u64>,
    json_output: bool,
) -> Result<(), CliError> {
    let passport: AgentPassport = serde_json::from_slice(&fs::read(input)?)?;
    let challenge: PassportPresentationChallenge =
        match (challenge_path, challenge_url) {
            (Some(path), None) => serde_json::from_slice(&fs::read(path)?)?,
            (None, Some(url)) => fetch_json_url(url)?,
            (Some(_), Some(_)) => {
                return Err(CliError::policy_error(
                    "challenge response accepts either --challenge or --challenge-url, not both"
                        .to_string(),
                ));
            }
            (None, None) => return Err(CliError::policy_error(
                "challenge response requires either --challenge <path> or --challenge-url <url>"
                    .to_string(),
            )),
        };
    let holder_keypair = load_existing_keypair(holder_seed_file)?;
    let response = respond_to_passport_presentation_challenge(
        &holder_keypair,
        &passport,
        &challenge,
        at.unwrap_or_else(unix_now),
    )?;

    ensure_parent_dir(output)?;
    fs::write(output, serde_json::to_vec_pretty(&response)?)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output": output.display().to_string(),
                "subject": response.passport.subject,
                "verifier": response.challenge.verifier,
                "nonce": response.challenge.nonce,
                "credentialCount": response.passport.credentials.len(),
            }))?
        );
    } else {
        println!("wrote challenge response to {}", output.display());
        println!("subject:          {}", response.passport.subject);
        println!("verifier:         {}", response.challenge.verifier);
        println!("nonce:            {}", response.challenge.nonce);
        println!("credential_count: {}", response.passport.credentials.len());
    }
    Ok(())
}

pub(crate) fn cmd_passport_challenge_submit(
    input: &Path,
    submit_url: &str,
    json_output: bool,
) -> Result<(), CliError> {
    let presentation: PassportPresentationResponse = serde_json::from_slice(&fs::read(input)?)?;
    let verification: chio_credentials::PassportPresentationVerification = post_json_url(
        submit_url,
        &VerifyPassportChallengeRequest {
            presentation,
            expected_challenge: None,
        },
    )?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&verification)?);
    } else {
        println!("presentation submitted");
        println!("accepted:         {}", verification.accepted);
        println!("subject:          {}", verification.subject);
        println!("verifier:         {}", verification.verifier);
        if let Some(challenge_id) = verification.challenge_id.as_deref() {
            println!("challenge_id:     {challenge_id}");
        }
        if let Some(replay_state) = verification.replay_state.as_deref() {
            println!("replay_state:     {replay_state}");
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_challenge_verify(
    input: &Path,
    challenge_path: Option<&Path>,
    verifier_policies_file: Option<&Path>,
    verifier_challenge_db: Option<&Path>,
    passport_statuses_file: Option<&Path>,
    at: Option<u64>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let response: PassportPresentationResponse = serde_json::from_slice(&fs::read(input)?)?;
    let expected_challenge = challenge_path
        .map(|path| -> Result<PassportPresentationChallenge, CliError> {
            Ok(serde_json::from_slice(&fs::read(path)?)?)
        })
        .transpose()?;
    let now = at.unwrap_or_else(unix_now);
    let verification = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .verify_passport_challenge(&VerifyPassportChallengeRequest {
                presentation: response,
                expected_challenge,
            })?
    } else {
        let challenge = expected_challenge.as_ref().unwrap_or(&response.challenge);
        let (resolved_policy, policy_source) =
            resolve_challenge_policy_local(challenge, verifier_policies_file, now)?;
        require_passport_lifecycle_source(
            resolved_policy
                .as_ref()
                .is_some_and(|policy| policy.require_active_lifecycle),
            passport_statuses_file,
            None,
        )?;
        let mut verification = verify_passport_presentation_response_with_policy(
            &response,
            expected_challenge.as_ref(),
            now,
            resolved_policy.as_ref(),
            policy_source,
        )
        .map_err(|error| CliError::policy_error(error.to_string()))?;
        let lifecycle = resolve_passport_lifecycle(
            &response.passport,
            now,
            passport_statuses_file,
            None,
            None,
            resolved_policy
                .as_ref()
                .is_some_and(|policy| policy.require_active_lifecycle),
        )?;
        apply_passport_lifecycle_to_presentation(&mut verification, lifecycle);
        if let Some(path) = verifier_challenge_db {
            PassportVerifierChallengeStore::open(path)?.consume(challenge, now)?;
            verification.replay_state = Some("consumed".to_string());
        }
        verification
    };
    let (enterprise_provenance_count, enterprise_provider_ids) =
        summarize_enterprise_provenance(&verification.enterprise_identity_provenance);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&verification)?);
    } else {
        println!("presentation verified");
        println!("subject:              {}", verification.subject);
        println!("passport_id:          {}", verification.passport_id);
        println!("verifier:             {}", verification.verifier);
        if let Some(challenge_id) = verification.challenge_id.as_deref() {
            println!("challenge_id:         {challenge_id}");
        }
        println!("nonce:                {}", verification.nonce);
        println!("accepted:             {}", verification.accepted);
        println!("policy_evaluated:     {}", verification.policy_evaluated);
        if let Some(policy_source) = verification.policy_source.as_deref() {
            println!("policy_source:        {policy_source}");
        }
        if let Some(policy_id) = verification.policy_id.as_deref() {
            println!("policy_id:            {policy_id}");
        }
        println!("credential_count:     {}", verification.credential_count);
        println!("valid_until:          {}", verification.valid_until);
        println!(
            "challenge_expires_at: {}",
            verification.challenge_expires_at
        );
        println!("enterprise_provenance: {}", enterprise_provenance_count);
        if !enterprise_provider_ids.is_empty() {
            println!(
                "enterprise_providers: {}",
                enterprise_provider_ids.join(", ")
            );
        }
        if let Some(lifecycle) = verification.passport_lifecycle.as_ref() {
            println!("lifecycle_state:      {}", lifecycle.state.label());
            if let Some(source) = lifecycle.source.as_deref() {
                println!("lifecycle_source:     {source}");
            }
        }
        if let Some(replay_state) = verification.replay_state.as_deref() {
            println!("replay_state:         {replay_state}");
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_oid4vp_request_create(
    args: PassportOid4vpRequestCreateArgs<'_>,
) -> Result<(), CliError> {
    let PassportOid4vpRequestCreateArgs {
        output,
        disclosure_claims,
        issuer_allowlist,
        ttl_secs,
        identity_subject,
        identity_continuity_id,
        identity_provider,
        identity_session_hint,
        identity_ttl_secs,
        json_output,
        control_url,
        control_token,
    } = args;
    let identity_assertion = match (identity_subject, identity_continuity_id) {
        (Some(subject), Some(continuity_id)) => Some(CreateIdentityAssertionRequest {
            subject: subject.to_string(),
            continuity_id: continuity_id.to_string(),
            provider: identity_provider.map(str::to_string),
            session_hint: identity_session_hint.map(str::to_string),
            ttl_seconds: identity_ttl_secs,
        }),
        (None, None) => None,
        _ => {
            return Err(CliError::transport_shape_error(
            "OID4VP identity assertion requires both --identity-subject and --identity-continuity-id"
                    .to_string(),
            ))
        }
    };
    let url = control_url.ok_or_else(|| {
        CliError::transport_shape_error(
            "OID4VP request creation requires --control-url because it depends on the running trust-control verifier service"
                .to_string(),
        )
    })?;
    let token = crate::require_control_token(control_token)?;
    let response = crate::trust_control::service_runtime::client::build_client(url, token)?
        .create_oid4vp_request(&CreateOid4vpRequest {
            disclosure_claims: disclosure_claims.to_vec(),
            issuer_allowlist: issuer_allowlist.to_vec(),
            ttl_seconds: ttl_secs,
            identity_assertion,
        })?;

    if let Some(path) = output {
        ensure_parent_dir(path)?;
        fs::write(path, serde_json::to_vec_pretty(&response)?)?;
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("OID4VP verifier request created");
        println!("request_id:       {}", response.transport.request_id);
        println!("request_uri:      {}", response.transport.request_uri);
        println!("same_device_url:  {}", response.transport.same_device_url);
        println!("cross_device_url: {}", response.transport.cross_device_url);
        println!(
            "descriptor_url:   {}",
            response.wallet_exchange.descriptor.descriptor_url
        );
        println!(
            "exchange_state:   {}",
            response.wallet_exchange.transaction.status.label()
        );
        if let Some(assertion) = response.wallet_exchange.identity_assertion.as_ref() {
            println!("identity_subject: {}", assertion.subject);
            println!("continuity_id:   {}", assertion.continuity_id);
        }
        println!("response_uri:     {}", response.transport.response_uri);
        println!("expires_at:       {}", response.transport.expires_at);
        if let Some(path) = output {
            println!("output:           {}", path.display());
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_oid4vp_respond(
    args: PassportOid4vpRespondArgs<'_>,
) -> Result<(), CliError> {
    let PassportOid4vpRespondArgs {
        input,
        request_url,
        same_device_url,
        cross_device_url,
        holder_seed_file,
        output,
        submit,
        submit_url,
        at,
        json_output,
    } = args;
    let resolved_request_url = match (request_url, same_device_url, cross_device_url) {
        (Some(url), None, None) => url.to_string(),
        (None, Some(url), None) | (None, None, Some(url)) => oid4vp_request_url_from_launch_url(url)?,
        (None, None, None) => {
            return Err(CliError::transport_shape_error(
            "OID4VP response requires one of --request-url, --same-device-url, or --cross-device-url"
                    .to_string(),
            ))
        }
        _ => {
            return Err(CliError::transport_shape_error(
            "OID4VP response accepts exactly one of --request-url, --same-device-url, or --cross-device-url"
                    .to_string(),
            ))
        }
    };
    if output.is_none() && !submit {
        return Err(CliError::transport_shape_error(
            "OID4VP response requires --output <path> unless --submit is set".to_string(),
        ));
    }

    let request_jwt = fetch_text_url(&resolved_request_url)?;
    let metadata_url = oid4vp_verifier_metadata_url(&resolved_request_url)?;
    let metadata: Oid4vpVerifierMetadata = fetch_json_url(&metadata_url)?;
    metadata
        .validate()
        .map_err(|error| CliError::policy_error(error.to_string()))?;
    if !resolved_request_url.starts_with(&metadata.request_uri_prefix) {
        return Err(CliError::transport_shape_error(
            "OID4VP request URL is outside the verifier metadata request_uri_prefix".to_string(),
        ));
    }
    let jwks: PortableJwkSet = fetch_json_url(&metadata.jwks_uri)?;
    let verifier_public_keys = verifier_public_keys_from_jwks(&jwks)?;
    let request: Oid4vpRequestObject = verify_signed_oid4vp_request_object_with_any_key(
        &request_jwt,
        &verifier_public_keys,
        at.unwrap_or_else(unix_now),
    )
    .map_err(|error| CliError::policy_error(error.to_string()))?;
    if request.request_uri != resolved_request_url {
        return Err(CliError::transport_shape_error(
            "OID4VP request JWT did not match the fetched request URL".to_string(),
        ));
    }
    if request.client_id != metadata.client_id {
        return Err(CliError::transport_shape_error(
            "OID4VP verifier metadata client_id did not match the signed request".to_string(),
        ));
    }

    let holder_keypair = load_existing_keypair(holder_seed_file)?;
    let portable_credential = load_text_file(input)?;
    let response_jwt = respond_to_oid4vp_request(
        &holder_keypair,
        &portable_credential,
        &request,
        at.unwrap_or_else(unix_now),
    )
    .map_err(|error| CliError::policy_error(error.to_string()))?;

    if let Some(path) = output {
        ensure_parent_dir(path)?;
        fs::write(path, response_jwt.as_bytes())?;
    }

    let submit_target = submit
        .then_some(request.response_uri.as_str())
        .or(submit_url);
    let verification = submit_target
        .map(|url| {
            post_form_url::<Oid4vpPresentationVerification>(url, &[("response", &response_jwt)])
        })
        .transpose()?;

    if json_output {
        let payload = if let Some(verification) = verification.as_ref() {
            serde_json::json!({
                "requestId": request.jti,
                "requestUri": request.request_uri,
                "responseUri": request.response_uri,
                "metadataUrl": metadata_url,
                "output": output.map(|path| path.display().to_string()),
                "submitted": true,
                "verification": verification,
            })
        } else {
            serde_json::json!({
                "requestId": request.jti,
                "requestUri": request.request_uri,
                "responseUri": request.response_uri,
                "metadataUrl": metadata_url,
                "output": output.map(|path| path.display().to_string()),
                "submitted": false,
            })
        };
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("OID4VP response created");
        println!("request_id:       {}", request.jti);
        println!("request_uri:      {}", request.request_uri);
        println!("response_uri:     {}", request.response_uri);
        println!("metadata_url:     {}", metadata_url);
        if let Some(path) = output {
            println!("output:           {}", path.display());
        }
        if let Some(verification) = verification.as_ref() {
            println!("submitted:        true");
            println!("verified_at:      {}", verification.verified_at);
            println!("passport_id:      {}", verification.passport_id);
            println!("subject_did:      {}", verification.subject_did);
            println!("issuer:           {}", verification.issuer);
        } else {
            println!("submitted:        false");
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_oid4vp_submit(
    input: &Path,
    submit_url: &str,
    json_output: bool,
) -> Result<(), CliError> {
    let response_jwt = load_text_file(input)?;
    let verification: Oid4vpPresentationVerification =
        post_form_url(submit_url, &[("response", response_jwt.as_str())])?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&verification)?);
    } else {
        println!("OID4VP response submitted");
        println!("request_id:   {}", verification.request_id);
        println!("passport_id:  {}", verification.passport_id);
        println!("subject_did:  {}", verification.subject_did);
        println!("issuer:       {}", verification.issuer);
        println!("verified_at:  {}", verification.verified_at);
        if let Some(transaction) = verification.exchange_transaction.as_ref() {
            println!("exchange_id:  {}", transaction.exchange_id);
            println!("exchange:     {}", transaction.status.label());
        }
        if let Some(assertion) = verification.identity_assertion.as_ref() {
            println!("identity:     {}", assertion.subject);
            println!("continuity:   {}", assertion.continuity_id);
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_oid4vp_metadata(
    verifier_url: &str,
    json_output: bool,
) -> Result<(), CliError> {
    let url = oid4vp_verifier_metadata_url(&format!(
        "{}/v1/public/passport/oid4vp/requests/example",
        verifier_url.trim_end_matches('/')
    ))?;
    let metadata: Oid4vpVerifierMetadata = fetch_json_url(&url)?;
    metadata
        .validate()
        .map_err(|error| CliError::policy_error(error.to_string()))?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&metadata)?);
    } else {
        println!("OID4VP verifier metadata");
        println!("verifier_id:      {}", metadata.verifier_id);
        println!("client_id:        {}", metadata.client_id);
        println!("request_prefix:   {}", metadata.request_uri_prefix);
        println!("response_uri:     {}", metadata.response_uri);
        println!("jwks_uri:         {}", metadata.jwks_uri);
        println!("trusted_key_count: {}", metadata.trusted_key_count);
    }
    Ok(())
}

pub(crate) fn cmd_passport_status_publish(
    input: &Path,
    passport_statuses_file: Option<&Path>,
    resolve_urls: &[String],
    cache_ttl_secs: Option<u64>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let passport: AgentPassport = serde_json::from_slice(&fs::read(input)?)?;
    let distribution = passport_status_distribution(resolve_urls, cache_ttl_secs);
    let record = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .publish_passport_status(&PublishPassportStatusRequest {
                passport,
                distribution,
            })?
    } else {
        let path = require_passport_status_registry_path(passport_statuses_file)?;
        let mut registry = load_passport_status_registry_for_admin(path)?;
        let record = registry.publish(&passport, unix_now(), distribution)?;
        registry.save(path)?;
        record
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("passport lifecycle published");
        println!("passport_id:   {}", record.passport_id);
        println!("subject:       {}", record.subject);
        println!("state:         {}", record.status.label());
        println!("issuer_count:  {}", record.issuer_count);
        println!("published_at:  {}", record.published_at);
        println!("updated_at:    {}", record.updated_at);
        if !record.distribution.resolve_urls.is_empty() {
            println!(
                "resolve_urls:  {}",
                record.distribution.resolve_urls.join(", ")
            );
        }
        if let Some(cache_ttl_secs) = record.distribution.cache_ttl_secs {
            println!("cache_ttl:     {cache_ttl_secs}");
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_status_list(
    passport_statuses_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .list_passport_statuses()?
    } else {
        let path = require_passport_status_registry_path(passport_statuses_file)?;
        let registry = load_passport_status_registry_for_admin(path)?;
        PassportStatusListResponse {
            configured: true,
            count: registry.passports.len(),
            passports: registry.passports.into_values().collect(),
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("configured: {}", response.configured);
        println!("count:      {}", response.count);
        for record in response.passports {
            println!(
                "- {} {} {}",
                record.passport_id,
                record.subject,
                record.status.label()
            );
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_status_get(
    passport_id: &str,
    passport_statuses_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let record = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .get_passport_status(passport_id)?
    } else {
        let path = require_passport_status_registry_path(passport_statuses_file)?;
        let registry = load_passport_status_registry_for_admin(path)?;
        registry.get(passport_id).cloned().ok_or_else(|| {
            CliError::policy_error(format!(
                "passport `{passport_id}` was not found in the lifecycle registry"
            ))
        })?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("passport_id:   {}", record.passport_id);
        println!("subject:       {}", record.subject);
        println!("state:         {}", record.status.label());
        println!("issuer_count:  {}", record.issuer_count);
        println!("published_at:  {}", record.published_at);
        println!("updated_at:    {}", record.updated_at);
        if let Some(superseded_by) = record.superseded_by.as_deref() {
            println!("superseded_by: {superseded_by}");
        }
        if let Some(revoked_at) = record.revoked_at {
            println!("revoked_at:    {revoked_at}");
        }
        if let Some(reason) = record.revoked_reason.as_deref() {
            println!("revoked_reason:{reason}");
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_status_resolve(
    passport_id: &str,
    passport_statuses_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let resolution = if let Some(url) = control_url {
        if control_token.is_some() {
            crate::trust_control::service_runtime::client::build_client(
                url,
                control_token.unwrap_or_default(),
            )?
            .resolve_passport_status(passport_id)?
        } else {
            crate::trust_control::service_runtime::client::build_public_client(url)?
                .public_resolve_passport_status(passport_id)?
        }
    } else {
        let path = require_passport_status_registry_path(passport_statuses_file)?;
        let registry = load_passport_status_registry_for_admin(path)?;
        let mut resolution = registry.resolve(passport_id);
        resolution.source = Some(format!("registry:{}", path.display()));
        resolution
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&resolution)?);
    } else {
        println!("passport_id:   {}", resolution.passport_id);
        println!("state:         {}", resolution.state.label());
        if !resolution.subject.is_empty() {
            println!("subject:       {}", resolution.subject);
        }
        if let Some(updated_at) = resolution.updated_at {
            println!("updated_at:    {updated_at}");
        }
        if let Some(source) = resolution.source.as_deref() {
            println!("source:        {source}");
        }
        if let Some(superseded_by) = resolution.superseded_by.as_deref() {
            println!("superseded_by: {superseded_by}");
        }
        if let Some(revoked_at) = resolution.revoked_at {
            println!("revoked_at:    {revoked_at}");
        }
        if let Some(reason) = resolution.revoked_reason.as_deref() {
            println!("revoked_reason:{reason}");
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_status_revoke(
    passport_id: &str,
    passport_statuses_file: Option<&Path>,
    reason: Option<&str>,
    revoked_at: Option<u64>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let record = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .revoke_passport_status(
                passport_id,
                &PassportStatusRevocationRequest {
                    reason: reason.map(str::to_string),
                    revoked_at,
                },
            )?
    } else {
        let path = require_passport_status_registry_path(passport_statuses_file)?;
        let mut registry = load_passport_status_registry_for_admin(path)?;
        let record = registry.revoke(passport_id, reason, revoked_at)?;
        registry.save(path)?;
        record
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("passport revoked");
        println!("passport_id:   {}", record.passport_id);
        println!("state:         {}", record.status.label());
        if let Some(revoked_at) = record.revoked_at {
            println!("revoked_at:    {revoked_at}");
        }
        if let Some(reason) = record.revoked_reason.as_deref() {
            println!("revoked_reason:{reason}");
        }
    }
    Ok(())
}
