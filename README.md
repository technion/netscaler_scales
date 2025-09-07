# Netscaler Scales

This is a mass Netscaler version scanner. Algorithms and workflow generally taken from this great Python based scanner:

https://github.com/fox-it/citrix-netscaler-triage/blob/main/scan-citrix-netscaler-version.py


## Features (planned)

- Rust based async code with a goal of faster, large scale scanning
- Output to an SQLite database for better management
- Resumable (sort of), will ignore IP addresses already in the database
- Release executable built for easy running from Windows
- Detailed "which CVE may apply to this version" is left to the user

## Use

- Create hosts.txt containing as many IP addresses as required
- Run the executable

## Code Goals

- No unsafe
- Panic free
- Resilient errors on any individual host