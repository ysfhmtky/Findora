# Findora

Findora is a versatile cybersecurity tool developed to automate the process of subdomain discovery and port scanning. It combines the power of popular tools like **Amass** and **Subfinder** for subdomain enumeration, and **Nmap** for scanning open ports on a target system. This project is intended for penetration testers, security enthusiasts, and anyone interested in scanning and analyzing networks and domains.

## Features

- **DNS Records** - A module to check DNS records of a given domain (currently not implemented, placeholder available).
- **Subdomain Finder** - Uses **Amass** and **Subfinder** to find subdomains for a given domain.
- **Port Scanner** - Uses **Nmap** to scan open ports of a target IP address or domain.

## Requirements

Before using Findora, you will need to install the following dependencies:

- Python 3.x
- **Nmap**: For port scanning.
- **Amass**: For subdomain enumeration (passive mode).
- **Subfinder**: Another tool for subdomain discovery.

## Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/ysfhmtky/Findora.git
    cd findora
    ```

2. Make sure you have the following tools installed on your system:
    - **Nmap**: [Installation Guide](https://nmap.org/book/install.html)
    - **Amass**: [Installation Guide](https://github.com/OWASP/Amass/blob/master/docs/installation.md)
    - **Subfinder**: [Installation Guide](https://github.com/projectdiscovery/subfinder#installation)

## Usage

1. Run the script:
    ```bash
    python findora.py
    ```

2. **Menu Options**:
    - **[1] DNS Records**: Check DNS records for a domain (Placeholder).
    - **[2] Subdomain Finder**: Use **Amass** and **Subfinder** to find subdomains of a target domain.
    - **[3] Port Scanner**: Scan open ports on a target domain or IP address.

3. **Subdomain Finder**: When choosing option 2, enter the target domain (e.g., `example.com`) to start the subdomain discovery process. Results will be saved in a CSV file and displayed in the terminal.

4. **Port Scanner**: When choosing option 3, enter the target domain or IP address (e.g., `example.com` or `192.168.1.1`) to perform a port scan. Open ports are displayed in the terminal.

### Example

```bash
Please choose an option:
[1] DNS Records
[2] Subdomain Finder
[3] Port Scanner

Enter your choice (1/2/3): 2
Enter the target domain (e.g., example.com): example.com
Finding subdomains for example.com using Findora...

Found 10 unique subdomains:
- sub1.example.com
- sub2.example.com
- ...

Subdomains saved to subdomains_example.com.csv
