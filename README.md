# rustpenguin

rustpenguin is a Rust-based port of the [mimipenguin](https://github.com/huntergregal/mimipenguin) tool, originally developed by Hunter Gregal. Inspired by the popular Windows security tool Mimikatz, Rustpenguin aims to extract plaintext credentials from process memory on Linux systems.

![example](https://akshayrohatgi.com/img/rustpenguin/working.png)

## Overview
**Blazing Fast**: Completes the search for credentials in just a few seconds, significantly faster than the original Python and shell versions.  
**Memory Dumping**: Extracts readable memory regions from vulnerable processes like Gnome Keyring.  
**Regex-Based Search**: Utilizes researched regex patterns ("needles") to find potential passwords within the dumped memory.  
**Password Verification**: Matches potential passwords against hashes in /etc/shadow to confirm valid credentials.  

For more details, check out my blog post [here](https://akshayrohatgi.com/blog/posts/rustpenguin)!

## Suppported Systems
rustpenguin has only been tested on Ubuntu Desktop 20.04 so far. The vulnerabilities in the applications it exploits seem to have been patched by the default versions available in Ubuntu 22.04.

## Building
Clone the repository and run the following command in the project root:

```bash
cargo build --release
```
This will generate a rustpenguin executable in the target/release directory.

## Usage
Run the executable with root permissions:
```
sudo ./rustpenguin
```
The tool will automatically identify vulnerable processes and attempt to extract and verify plaintext passwords.

