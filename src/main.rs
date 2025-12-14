use minsc::{eval, parse, Error, ExprRepr, PrettyDisplay, Value};
use std::io::{self, Read};
use std::{env, fs, process::ExitCode};

fn main_() -> Result<ExitCode, Error> {
    let mut args = env::args();
    let input = args.nth(1);
    let rest = args.collect::<Vec<_>>();
    let print_ast = rest.iter().any(|arg| arg == "--ast");
    let repr_res = rest.iter().any(|arg| arg == "--repr");
    let explicit_res = rest.iter().any(|arg| arg == "--explicit");

    let mut code = String::new();
    match input.as_deref() {
        None | Some("-") => io::stdin().read_to_string(&mut code)?,
        Some(path) => fs::File::open(path)?.read_to_string(&mut code)?,
    };

    if print_ast {
        println!("{:#?}", parse(&code)?);
        return Ok(ExitCode::SUCCESS);
    }

    let res = eval(&code)?;

    if repr_res {
        print!("{}", res.repr_str());
    } else if !explicit_res {
        // Pretty display optimized for console output
        match &res {
            // Unnecessary to print return values of `true`, the SUCCESS exit code is enough
            Value::Bool(true) => {}
            // Print raw strings in multi-line with no quoting
            Value::String(string) => println!("{}", string),
            _ => println!("{}", res.pretty_multiline()),
        }
    } else {
        // Pretty display with quoted strings and explicit `true`, for non-console use (by other programs)
        print!("{}", res.pretty_multiline())
    }

    Ok(if res == Value::Bool(false) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

// Wrap main() to customize error handling (print using Display rather than Debug)
fn main() -> ExitCode {
    main_().unwrap_or_else(|err| {
        eprintln!("{}", err);
        ExitCode::FAILURE
    })
}
