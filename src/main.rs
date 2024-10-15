use minsc::{eval, parse, Error, PrettyDisplay, Value};
use std::io::{self, Read};
use std::{env, fs, process::ExitCode};

fn main_() -> Result<ExitCode, Error> {
    let mut args = env::args();
    let input = args.nth(1).unwrap_or_else(|| "-".into());
    let print_ast = args.next().is_some_and(|arg| arg == "--ast");

    let mut code = String::new();
    match &*input {
        "-" => io::stdin().read_to_string(&mut code)?,
        file => fs::File::open(file)?.read_to_string(&mut code)?,
    };

    Ok(if print_ast {
        println!("{:#?}", parse(&code)?);
        ExitCode::SUCCESS
    } else {
        let res = eval(&code)?;
        match &res {
            // Unnecessary to print return values of `true`, the SUCCESS exit code is enough
            Value::Bool(true) => {}
            // Print raw strings with no quoting
            Value::String(string) => print!("{}", string),
            _ => println!("{}", res.pretty_multiline()),
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
