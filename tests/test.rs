use minsc::run;

fn test(minsc: &str, expected_policy: &str) {
    let res = run(&replace_dummy(minsc)).unwrap();
    let policy = res.into_policy().unwrap().to_string();
    assert_eq!(policy, replace_dummy(expected_policy));
}

#[test]
fn test_policy_is_valid_minsc() {
    test("pk(A)", "pk(A)");
    test("and(pk(A), older(9))", "and(pk(A),older(9))");
    test("or(3@pk(A), 2@pk(B))", "or(3@pk(A),2@pk(B))");
}

#[test]
fn test_infix_or() {
    test("pk(A) || pk(B)", "or(1@pk(A),1@pk(B))");
    test("pk(A) || pk(B) || pk(C)", "thresh(1,pk(A),pk(B),pk(C))");
}

#[test]
fn test_infix_and() {
    test("pk(A) && pk(B)", "and(pk(A),pk(B))");
    test("pk(A) && pk(B) && pk(C)", "thresh(3,pk(A),pk(B),pk(C))");
}

#[test]
fn test_probs() {
    test("10@pk(A) || pk(B)", "or(10@pk(A),1@pk(B))");
    test("likely@pk(A) || pk(B)", "or(10@pk(A),1@pk(B))");
    test("prob(10, pk(A)) || pk(B)", "or(10@pk(A),1@pk(B))");
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
        "or(10@and(pk(A),sha256(H)),1@and(pk(B),older(10)))",
    );
}

#[test]
fn test_functions() {
    test(
        r"
        fn two_factor($user, $provider, $delay) = 
          $user && (likely@$provider || older($delay));

        $user = pk(A) && pk(B);
        $providers = [ pk(C), pk(D), pk(E) ];

        two_factor($user, 2 of $providers, 4 months)
        ",
        "and(and(pk(A),pk(B)),or(10@thresh(2,pk(C),pk(D),pk(E)),1@older(4214850)))",
    );
}

fn replace_dummy(s: &str) -> String {
    s.replace(
        "A",
        "0381e3019c5861c2e0bd33604ec5c3e37cbb67dbbd7fadf9567232a30acfde204c",
    )
    .replace(
        "B",
        "0399e3019c5861c2e0bd33604ec5c3e37cbb67dbbd7fadf9567232a30acfde204c",
    )
    .replace(
        "C",
        "0377e3019c5861c2e0bd33604ec5c3e37cbb67dbbd7fadf9567232a30acfde204c",
    )
    .replace(
        "D",
        "0366e3019c5861c2e0bd33604ec5c3e37cbb67dbbd7fadf9567232a30acfde204c",
    )
    .replace(
        "E",
        "0355e3019c5861c2e0bd33604ec5c3e37cbb67dbbd7fadf9567232a30acfde204c",
    )
    .replace(
        "H",
        "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
    )
}
