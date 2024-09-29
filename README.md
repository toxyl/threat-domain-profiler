# Threat Domain Profiler

## Overview

The **Threat Domain Profiler** is a Go-based tool designed to gather and profile domain information, including IP addresses, hostnames, and abuse contact details. This tool is particularly useful for security analysts and researchers who need to quickly gather and analyze domain-related data for threat intelligence purposes.

The tool leverages DNS queries and WHOIS lookups to gather the necessary information. It supports multiple output formats (CSV, YAML, JSON) and can be configured to use custom DNS servers and abuse contact lists.

## Features

- **Domain Information Gathering**: Collects domain names, IP addresses, hostnames, and abuse contact information.
- **Custom DNS Servers**: Allows the use of a custom list of DNS servers for DNS queries.
- **Abuse Contact Lookup**: Uses a combination of known abuse contacts and WHOIS lookups to find abuse contact information.
- **Output Formats**: Supports output in CSV, YAML, and JSON formats.
- **Concurrent Processing**: Utilizes goroutines to process multiple domains concurrently, improving performance.
- **Flexible Domain Input**: Domains can be provided via:
  - Standard input (stdin)
  - Command-line arguments
  - A file specified by the `-d` flag

## Prerequisites
This tool requires `whois` and `dig` to be present. 

## Installation

To install the Threat Domain Profiler, you need to have Go installed on your system. Follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/toxyl/threat-domain-profiler.git
   cd threat-domain-profiler
   ```

2. Build the project:
   ```bash
   go build -o threat-domain-profiler
   ```

3. Run the tool:
   ```bash
   ./threat-domain-profiler -d domains.txt -o csv
   ```

## Usage

### Command-Line Options

- `-dns`: File containing a list of DNS servers to use. If not provided, the tool will use a default list embedded in the binary.
- `-d`: File containing a list of domain names to profile. If not provided, the tool will expect domain names as command-line arguments and/or via stdin.
- `-o`: Output format. Supported formats are `csv`, `yaml`, and `json`. Default is `csv`.
- `-w`: Number of worker goroutines to use for processing domains. Default is 5.
- `-c`: File containing a list of known abuse contacts in YAML format. If not provided, the tool will use a default list embedded in the binary.

### Example Usage

```bash
./threat-domain-profiler -d domains.txt -o json -w 10 -c contacts.yaml -dns dns_servers.txt
```

This command will:
- Use `domains.txt` as the list of domains to profile.
- Output the results in JSON format.
- Use 10 worker goroutines.
- Use `contacts.yaml` for known abuse contacts.
- Use `dns_servers.txt` for the list of DNS servers.

### Input Files

#### DNS Servers File

The DNS servers file should contain one DNS server per line. Example:

```
8.8.8.8
8.8.4.4
1.1.1.1
```

#### Domains File

The domains file should contain one domain per line. Example:

```
example.com
anotherexample.com
yetanotherexample.com
```

#### Abuse Contacts File

The abuse contacts file should be in YAML format, with domains or IP addresses mapped to abuse contact emails. Example:

```yaml
example.com: abuse@example.com
192.0.2.1: abuse@isp.com
```

### Providing Domains

Domains can be provided in three ways:

1. **Via Standard Input (stdin)**:
   ```bash
   cat domains.txt | ./threat-domain-profiler -o yaml
   ```

2. **Via Command-Line Arguments**:
   ```bash
   ./threat-domain-profiler example.com anotherexample.com -o json
   ```

3. **Via the `-d` Flag**:
   ```bash
   ./threat-domain-profiler -d domains.txt -o csv
   ```

Any combination of the above methods is valid as long as at least one method is used.

### Output

The tool will output the gathered domain information in the specified format. For example, in CSV format:

```
Domain	IP	Hostname	Abuse Contact
example.com	93.184.216.34	example.com	abuse@example.com
anotherexample.com	192.0.2.1	anotherexample.com	abuse@isp.com
```

## Contributing

Contributions to the Threat Domain Profiler are welcome! Please feel free to submit issues, pull requests, or suggestions for improvements.

## License

This project is released into the public domain under the UNLICENSE.
