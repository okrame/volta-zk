fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    match volta_pcs::c71_matrix::canonical_reference(&arguments) {
        Ok(report) => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
