//! `identity-enrol enrol --machine-dir D --key K --dir X` (see
//! `identity_keyfile::enrol_cli`).

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match identity_keyfile::enrol_cli::run(&args, None) {
        Ok(outcome) => {
            println!("{outcome:?}");
        }
        Err(error) => {
            eprintln!("{}: {error}", error.code());
            std::process::exit(1);
        }
    }
}
