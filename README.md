# aslookup

`aslookup` is a C program that performs Autonomous System Number (ASN) lookup for a given IP address. It uses raw DNS queries to Team Cymru's ASN mapping service to retrieve ASN information, then securely fetches associated IP ranges from HackerTarget using HTTPS via libcurl.

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
./aslookup
```

Then enter an IP address when prompted:

```
Enter IP address: 94.231.103.111
```
Example output:
```
~$ ./aslookup
Enter IP address: 94.231.103.111

Resolved ASN: 48854

IP Ranges:
"48854","TEAM-BLUE-DENMARK, DK"
.
94.231.96.0/20
.

ASN Number: 48854
Name: team-blue-denmark
Description: team.blue Denmark A/S
Country: DK
Website: https://dkcareers.team.blue/pages/brands

Email Contacts:
  - dk-abuse@team.blue
  - info@zitcom.dk
  - dk-noc@team.blue
  - noc@zitcom.dk

Abuse Contacts:
  - dk-abuse@team.blue

Owner Address:
  Hoejvangen 4
  8660
  Skanderborg
  DENMARK

Traffic Ratio: Mostly Outbound
Updated: 2025-08-27 05:46:20
```
## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Author

Niel Nielsen
