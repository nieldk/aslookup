# aslookup

`aslookup` is a C program that performs Autonomous System Number (ASN) lookup for a given IP address. It uses raw DNS queries to Team Cymru's ASN mapping service to retrieve ASN information, then securely fetches associated IP ranges from HackerTarget using HTTPS via libcurl.

## Features

- Raw DNS query to Team Cymru to resolve ASN from IP address
- Correctly parses TXT DNS records to extract full ASN (including leading digits)
- Secure HTTPS request to HackerTarget ASN lookup API using libcurl
- Displays IP ranges and organization details for the ASN
- Fully self-contained: no external tools like `whois`, `dig`, or `curl` required

## Installation

### Prerequisites

- GCC compiler
- libcurl development library

### Install libcurl (Debian/Ubuntu)


sudo apt-get install libcurl4-openssl-dev

### Compile

```bash
gcc aslookup.c -o aslookup -lcurl
```

## Usage

```bash
./aslookup
```

Then enter an IP address when prompted:

```
Enter IP address: 194.116.222.40
```

Example output:


ASN Info: 21060 | 194.116.222.0/24 | DK | ripencc | 2005-02-16

Querying HackerTarget for ASN 21060...

194.116.222.0/24
194.116.223.0/24
...

## Dependencies

- POSIX-compatible system
- libcurl for HTTPS requests

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Author

Niel Nielsen
