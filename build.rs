fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    let toml = std::fs::read_to_string("Cargo.toml").expect("Failed to read Cargo.toml");
    for line in toml.lines().filter(|l| l.contains("pingora =")) {
        if let Some(version) = line.find('"').and_then(|start| {
            line[start + 1..]
                .find('"')
                .map(|end| &line[start + 1..start + 1 + end])
        }) {
            println!("cargo:rustc-env=PINGORA_VERSION={version}");
            return;
        }
    }
    println!("cargo:rustc-env=PINGORA_VERSION=unknown");
}
