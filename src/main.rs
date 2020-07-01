#[macro_use] extern crate lalrpop_util;

//lalrpop_mod!(pub test);
lalrpop_mod!(pub grammar);

fn main(){}

#[test]
fn test() {
  let parser = grammar::ProgramParser::new();
  println!("{:#?}", parser.parse("let $foo = (bar || baz); $foo").unwrap());
  println!("{:#?}", parser.parse("fn foo($bar) = qux($bar); foo(3)").unwrap());
  println!("{:#?}", parser.parse("fn foo($bar) { let $bar = taz(1); qux($bar) }; foo(6)").unwrap());
}
