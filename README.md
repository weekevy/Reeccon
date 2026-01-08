# Project Overview

This project, `netdom`, is a collection of bash scripts designed for domain enumeration. It provides modules for both passive and active reconnaissance, as well as a utility for filtering subdomains based on their level.

The main script, `netdom.sh`, acts as a dispatcher, calling the different modules based on the user's input. The available modules are:

- **passive.sh**: Performs passive subdomain enumeration using a variety of open-source tools and services, including Subfinder, Assetfinder, Findomain, Chaos, crt.sh, and DNSRecon.
- **active.sh**: Performs active subdomain enumeration through brute-forcing using MassDNS and dnsx.
- **level.sh**: Extracts subdomains from a given list based on a specified depth (level).

This project is intended for security professionals and bug bounty hunters who need to quickly and effectively enumerate subdomains for a given target.

# Building and Running

This project does not require a build process. However, it has several dependencies that need to be installed for the scripts to function correctly.

## Dependencies

### Passive Module (`passive.sh`)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [findomain](https://github.com/findomain/findomain)
- [chaos-client](https://github.com/projectdiscovery/chaos-client)
- [dnsrecon](https://github.com/darkoperator/dnsrecon)
- [jq](https://stedolan.github.io/jq/)
- [curl](https://curl.se/)

### Active Module (`active.sh`)
- [massdns](https://github.com/blechschmidt/massdns)
- [dnsx](https://github.com/projectdiscovery/dnsx)

## Running the scripts

The main script `netdom.sh` is used to run the different modules.

### Show Help Message
```bash
./netdom.sh -h
```

### Passive Enumeration
```bash
./netdom.sh passive -d <domain> [-o <output_file>]
```
**Example:**
```bash
./netdom.sh passive -d example.com -o subs.txt
```

### Active Enumeration
```bash
./netdom.sh active -d <domain> -w <wordlist>
```
**Example:**
```bash
./netdom.sh active -d example.com -w /path/to/wordlist.txt
```

### Level Extraction
```bash
./netdom.sh level -l <domain_list> -level <level>
```
**Example:**
```bash
./netdom.sh level -l subs.txt -level 2
```

# Development Conventions

This project consists of a set of bash scripts. There are no formal development conventions enforced, but the code is well-structured and easy to read. Each script has a clear purpose and includes a usage function that explains the available options. The scripts make use of color-coded output to improve readability.
