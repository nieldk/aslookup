# aslookup

`aslookup` is a C program that performs Autonomous System Number (ASN) lookup for a given IP address or domain.
It uses raw DNS queries to Team Cymru's ASN mapping service to retrieve ASN information, then securely fetches associated IP ranges from HackerTarget using HTTPS via libcurl and contactinformation using bgpview (sadly this often returns an Internal Server error).

## Features

- Raw DNS query to Team Cymru to resolve ASN from IP address
- Correctly parses TXT DNS records to extract full ASN (including leading digits)
- Secure HTTPS request to HackerTarget ASN lookup API using libcurl
- Displays IP ranges and organization details for the ASN
- Displays contact information on the found ASN
- Fully self-contained: no external tools like `whois`, `dig`, or `curl` required

## Installation

### Prerequisites

- GCC compiler
- libcurl development library
- libjcon development library
- libc6 development library

### Install libcurl libjcon-dev libc6-dev (Debian/Ubuntu)


sudo apt-get install libcurl4-openssl-dev libc6-dev

### Compile

```bash
gcc aslookup.c -o aslookup -lcurl -lcjson -lresolv
```

## Usage

```bash
aslookup <options>
Options:
 -i <IP[,IP,...]> Specify one or more IP addresses (comma-separated)
 -d <domain[,domain,...]> Specify one or more domain names (comma-separated)
 -f <file> Save output to a formatted text file
 --help Show this help message
 --version Show latest GitHub release version
```

Example output:

![screenshot](sample-output.jpg)


### Releases

There are packages for Ubuntu, Arch and Alpine Linux in releases
Install with:

Ubuntu:

```bash
sudo dpkg -i aslookup_<version>_amd64.deb
```

Arch:

```bash
sudo pacman -U aslookup-<version>-x86_64.pkg.tar.zst
```

Alpine:

```bash
sudo apk add --allow-untrusted aslookup_<version>_x86_64.apk
```

## Arch Linux Users

If you find this package useful, please consider voting for it on the AUR!  
More votes help increase visibility and the chance for inclusion in official Arch repositories.

To vote, log in to the AUR website and click the "Vote" button on the package page.

[You can find and vote for this package on the AUR page](https://aur.archlinux.org/packages/aslookup)

Thank you for your support!

## License

This project is licensed under the BSD Zero Clause License. See the LICENSE file for details.

## Author

Niel Nielsen
