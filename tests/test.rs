use minsc::compile;

fn test(minsc: &str, expected_policy: &str) {
    let policy = compile(minsc).unwrap().to_string();
    assert_eq!(policy, expected_policy);
}

#[test]
fn test_policy_is_valid_minsc() {
    test("pk(A)", "pk(A)");
    test("and(pk(A), older(9))", "and(pk(A),older(9))");
    test("or(3@pk(A), 2@pk(B))", "or(3@pk(A),2@pk(B))");
}

#[test]
fn test_infix_or() {
    test("pk(A) || pk(B)", "or(pk(A),pk(B))");
    test("pk(A) || pk(B) || pk(C)", "thresh(1,pk(A),pk(B),pk(C))");
}

#[test]
fn test_infix_and() {
    test("pk(A) && pk(B)", "and(pk(A),pk(B))");
    test("pk(A) && pk(B) && pk(C)", "thresh(3,pk(A),pk(B),pk(C))");
}

#[test]
fn test_probs() {
    test("10@pk(A) || pk(B)", "or(10@pk(A),pk(B))");
    test("likely@pk(A) || pk(B)", "or(10@pk(A),pk(B))");
    test("prob(10, pk(A)) || pk(B)", "or(10@pk(A),pk(B))");
    test("likely(pk(A)) || pk(B)", "or(10@pk(A),pk(B))");
}

#[test]
fn test_datetime() {
    test("after(2030-01-01)", "after(1893456000)");
    test("after(2030-01-01 13:37)", "after(1893505020)");
}

#[test]
fn test_durations() {
    test("older(1 day)", "older(4194473)");
    test("older(3 months 2 weeks)", "older(4212076)");
    test("older(heightwise 1 day)", "older(144)");
}

#[test]
fn test_variables() {
    test(
        r"
        $redeem = pk(A) && sha256(H);
        $refund = pk(B) && older(10);

        likely@$redeem || $refund
        ",
        "or(10@and(pk(A),sha256(H)),and(pk(B),older(10)))",
    );
}

#[test]
fn test_functions() {
    test(
        r"
        fn two_factor($user, $provider, $delay) = 
          $user && (likely@$provider || older($delay));

        $user = pk(user_desktop) && pk(user_mobile);
        $providers = [ pk(P1), pk(P2), pk(P3), pk(P4) ];

        two_factor($user, 3 of $providers, 4 months)
        ",
        "and(and(pk(user_desktop),pk(user_mobile)),or(10@thresh(3,pk(P1),pk(P2),pk(P3),pk(P4)),older(4214850)))",
    );
}
