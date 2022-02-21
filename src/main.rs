use minsc::{eval, parse, Result};
use std::{env, fs, io};

fn main() -> Result<()> {
    let mut args = env::args();
    let input = args.nth(1).unwrap_or_else(|| "-".into());

    let arg = args.next();
    let print_ast = arg == Some("--ast".into());
    let debug = arg == Some("--debug".into());

    let mut reader: Box<dyn io::Read> = match &*input {
        "-" => Box::new(io::stdin()),
        _ => Box::new(fs::File::open(input)?),
    };

    let mut code = String::new();
    reader.read_to_string(&mut code)?;

    if print_ast {
        println!("{:#?}", parse(&code)?);
    } else {
        let res = eval(parse(&code)?)?;
        println!("{}", res);
        if debug {
            println!("\n\n{:#?}", res);
        }
    }

    Ok(())
}
