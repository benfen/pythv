# pythv

Toy project to try and find vulnerabilities in a provided requirements.txt based on the nvd CVE database.

## Running

If you have `cargo` and `rust` installed, use `cargo build --release` to regenerate the binary from the source.  Otherwise, the binary is bundled with the repo and can be used directly

These commands must be run from the root of the repo as things stand.

* `./load-cves.sh` - Fetches the CVE json files from the NVD database
* `./target/release/pythv <REQUIREMENTS_FILE>` - Scans the requirements file and returns a list of possible vulnerabilities and associated CVE ids.
