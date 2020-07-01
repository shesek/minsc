#[macro_use]
extern crate lalrpop_util;

//lalrpop_mod!(pub test);
lalrpop_mod!(pub grammar);

fn main() {}

#[test]
fn test() {
    let parser = grammar::ProgramParser::new();
    println!("{:#?}", parser.parse("let $foo = (bar || baz); $foo").unwrap());
    println!("{:#?}", parser.parse("fn foo($bar,) = qux($bar); foo(123)").unwrap());
    println!(
        "{:#?}",
        parser.parse("fn foo($bar) { let $t = taz(1); qux($t) }; foo(abc)").unwrap()
    );
}
