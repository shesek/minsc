use minsc::{eval, parse, Error, PrettyDisplay, Value};
use std::{env, fs, io, process::ExitCode};

fn main_() -> Result<ExitCode, Error> {
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

    Ok(if print_ast {
        println!("{:#?}", parse(&code)?);
        ExitCode::SUCCESS
    } else {
        let res = eval(parse(&code)?)?;
        // Unnecessary to print return values of `true`, the SUCCESS exit code is sufficient
        if res != Value::Bool(true) {
            println!("{}", res.pretty_multiline());
        }
        if debug {
            println!("\n\n{:#?}", res);
        }
        if res == Value::Bool(false) {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    })
}

// Wrap main() to customize error handling (print using Display rather than Debug)
fn main() -> ExitCode {
    main_().unwrap_or_else(|err| {
        eprintln!("{}", err);
        ExitCode::FAILURE
    })
}
