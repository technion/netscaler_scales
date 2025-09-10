# Netscaler Scales

This is a mass Netscaler version scanner. Algorithms and workflow generally taken from this great Python based scanner:

https://github.com/fox-it/citrix-netscaler-triage/blob/main/scan-citrix-netscaler-version.py


## Features (planned)

- Rust based async code with a goal of faster, large scale scanning
- Outputs to CSV. (SQLite has been abandoned due to concurency issues I couldn't fix)
- Resumable (sort of), will ignore IP addresses already in the database
- Release executable built for easy running from Windows
- Detailed "which CVE may apply to this version" is left to the user

## Use

- Create hosts.txt containing as many IP addresses as required
- Run the executable
- This was designed with Windows in mind but I couldn't get the network stack to not fall over

## Code Goals

- No unsafe
- Panic free
- Resilient errors on any individual host

## Running
- Increase ulimit with `ulimit -n 32768`
- Create a hosts.txt file
- Run it
