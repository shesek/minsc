#[macro_use]
extern crate lalrpop_util;

//lalrpop_mod!(pub test);
lalrpop_mod!(pub grammar);

fn main() {}

#[test]
fn test() {
    let parser = grammar::ExprParser::new();
    println!("{:#?}", parser.parse("let $foo = (bar || baz)").unwrap());
    println!("{:#?}", parser.parse("fn foo($bar,) = qux($bar)").unwrap());
    println!(
        "{:#?}",
        parser.parse("fn foo($bar) { taz(1); qux($bar) }").unwrap()
    );
}
