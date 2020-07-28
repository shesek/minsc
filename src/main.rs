use minsc::{compile, parse, Result};
use std::{env, fs, io};

fn main() -> Result<()> {
    let mut args = env::args();
    let input = args.nth(1).unwrap_or_else(|| "-".into());
    let print_ast = args.next() == Some("--ast".into());

    let mut reader: Box<dyn io::Read> = match &*input {
        "-" => Box::new(io::stdin()),
        _ => Box::new(fs::File::open(input)?),
    };

    let mut code = String::new();
    reader.read_to_string(&mut code)?;

    if print_ast {
        println!("{:#?}", parse(&code)?);
    } else {
        println!("{}", compile(&code)?);
    }

    Ok(())
}
