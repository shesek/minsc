#[macro_use]
extern crate lalrpop_util;

use minis::execution::Evaluate;
use minis::Scope;

lalrpop_mod!(pub grammar);

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
}

fn try_minis(s: &str) {
    let parser = grammar::ProgramParser::new();
    let ast = parser.parse(s).unwrap();
    println!("AST: {:#?}", ast);

    let scope = Scope::root();
    let res = ast.eval(&scope).unwrap();
    println!("eval: {:#?}", res);

    let res = res.into_policy().unwrap();
    println!("policy: {:#?}", res);
}
