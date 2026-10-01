//! `bitty-net` executable: serves wire protocol v1 on stdin/stdout.
//!
//! Usage: `bitty-net` (serve) or `bitty-net --version`. Any other argument
//! is refused. The Bitty core spawns this binary; it is not an interactive
//! tool.

#![forbid(unsafe_code)]

use std::io::{BufReader, stdin, stdout};
use std::process::ExitCode;
use std::sync::Arc;

use bitty_net::{COMPONENT_VERSION, EXIT_PROTOCOL, HttpBackend, ServeConfig, serve};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next()) {
        (None, _) => {}
        (Some(flag), None) if flag == "--version" || flag == "-V" => {
            println!("bitty-net {COMPONENT_VERSION}");
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("usage: bitty-net [--version]");
            return ExitCode::from(EXIT_PROTOCOL);
        }
    }
    let input = BufReader::new(stdin());
    let outcome = serve(
        input,
        stdout(),
        Arc::new(HttpBackend),
        &ServeConfig::default(),
    );
    ExitCode::from(outcome.exit_code())
}
