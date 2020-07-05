use minis::{parse, run};

fn main() {}

#[test]
fn test() {
    /*
    println!(
        "{:#?}",
        parser.parse("let $foo = (bar || baz); $foo").unwrap()
    );
    println!(
        "{:#?}",
        parser.parse("fn foo($bar,) = qux($bar); foo(123)").unwrap()
    );*/

    //try_minis("fn foo($bar) { let $t = taz(1); $t }; foo(abc)");
    try_minis("fn foo($bar) { let $t = sha256($bar); $t }; foo(abc)");
    try_minis("fn foo($bar, $fn) { let $t = $fn($bar); $t }; foo(abc, hash160)");
}

fn try_minis(s: &str) {
    let ast = parse(s).unwrap();
    println!("AST: {:#?}", ast);

    let res = run(ast).unwrap();
    println!("result: {:#?}", res);

    let policy = res.into_policy().unwrap();
    println!("policy: {:#?}", policy);
    println!("policy str: {}", policy);
}
