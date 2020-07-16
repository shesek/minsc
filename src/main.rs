use minis::{compile, parse, run, Result};
use std::{env, fs, io};

fn main() -> Result<()> {
    let input = env::args().nth(1).unwrap_or("-".into());
    let mut reader: Box<dyn io::Read> = match &*input {
        "-" => Box::new(io::stdin()),
        _ => Box::new(fs::File::open(input)?),
    };

    let mut code = String::new();
    reader.read_to_string(&mut code)?;

    let policy = compile(&code)?;

    println!("{}", policy);

    Ok(())
}
