#[test]
fn governed_denial_does_not_block_later_matching_grant() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let governed =
        make_governed_monetary_grant("srv-a", "read_file", 100, 1_000, "USD", 50);
    let mut fallback = make_grant("srv-a", "read_file");
    fallback.max_invocations = Some(2);
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![governed, fallback]),
        300,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "governed-grant-fallback",
            &capability,
            "read_file",
            "srv-a",
        ))
        .expect("evaluate fallback grant");

    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(
        kernel
            .budget_store
            .get_usage(&capability.id, 1)
            .expect("fallback usage")
            .expect("fallback grant was charged")
            .invocation_count,
        1
    );
}
