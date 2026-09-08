fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = (|| -> Result<serde_json::Value, String> {
        let n = args
            .get(1)
            .ok_or("usage: c71_matrix preflight|run N [state-directory]")?
            .parse()
            .map_err(|_| "invalid matrix dimension")?;
        match args[0].as_str() {
            #[cfg(feature = "c71-work-census")]
            "census-check" => volta_pcs::c71_matrix::self_check(),
            "preflight" => volta_pcs::c71_matrix::preflight(n),
            "run" => volta_pcs::c71_matrix::run(
                n,
                std::path::Path::new(args.get(2).ok_or("state directory required")?),
            ),
            _ => Err("unknown command".into()),
        }
    })();
    match result {
        Ok(report) => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
