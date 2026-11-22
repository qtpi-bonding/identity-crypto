//! Thin front end: parse args, load config, start the server.

use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path: Option<String> = None;
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--config" => {
                config_path = iter.next().cloned();
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let path = match config_path {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            eprintln!("usage: identity-request-signer --config PATH");
            std::process::exit(2);
        }
    };
    let config = match identity_request_signer::Config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", coded_error::CodedError::code(&e));
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let clock: Arc<dyn identity_request_auth::Clock> = Arc::new(identity_request_auth::SystemClock);
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|line| eprintln!("{line}"));
    let mut server = match identity_request_signer::Server::new(config, clock, log.clone()) {
        Ok(s) => s,
        Err(e) => {
            log(&format!(
                "start refused: {}",
                coded_error::CodedError::code(&e)
            ));
            std::process::exit(1);
        }
    };
    if let Err(e) = server.register_op(Box::new(identity_request_signer::SignRequestOp::new())) {
        log(&format!(
            "start refused: {}",
            coded_error::CodedError::code(&e)
        ));
        std::process::exit(1);
    }
    let bound = match server.bind() {
        Ok(b) => b,
        Err(e) => {
            log(&format!(
                "start refused: {}",
                coded_error::CodedError::code(&e)
            ));
            std::process::exit(1);
        }
    };
    let running = bound.spawn();
    std::thread::park();
    running.stop();
}
