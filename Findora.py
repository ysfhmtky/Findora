import subprocess
import pyfiglet
from colorama import Fore, init
import dns.resolver
import sys
import os
import re
import requests
from datetime import datetime

os.system("clear")

init()

ascii_art = pyfiglet.figlet_format("Findora", font="slant")

def print_header():
    print(Fore.BLUE + ascii_art)
    print(Fore.LIGHTGREEN_EX + "            - By Mr.CodeX")
    print(Fore.CYAN + "\nPlease choose an option:")
    print(Fore.YELLOW + "[1] DNS Records")
    print(Fore.YELLOW + "[2] Subdomain Finder")
    print(Fore.YELLOW + "[3] Port Scanner")

def get_choice():
    try:
        return input(Fore.CYAN + "\nEnter your choice (1/2/3): ").strip()
    except KeyboardInterrupt:
        print(Fore.RED + "\nProgram interrupted by user. Exiting...")
        sys.exit(0)

def get_dns_records(domain):
    try:
        print(Fore.CYAN + f"\nFetching DNS records for {domain}...\n")
        for record_type in ["A", "MX", "NS", "TXT", "CNAME"]:
            print(Fore.YELLOW + f"\n{record_type} Records:")
            try:
                records = dns.resolver.resolve(domain, record_type)
                for record in records:
                    print(Fore.GREEN + record.to_text())
            except dns.resolver.NoAnswer:
                print(Fore.RED + f"No {record_type} records found.")
            except Exception as e:
                print(Fore.RED + f"Error fetching {record_type} records: {e}")
    except Exception as e:
        print(Fore.RED + f"Error fetching DNS records: {e}")

def find_subdomains(domain):
    try:
        print(Fore.CYAN + f"\nFetching subdomains for {domain} from Findora...\n")
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            subdomains = set()

            for entry in data:
                name_value = entry.get("name_value", "")
                subdomains.update(name_value.splitlines())

            subdomains = sorted(subdomains)

            print(Fore.GREEN + "\nSubdomains found:")
            for subdomain in subdomains:
                print(Fore.YELLOW + subdomain)

            timestamp = datetime.now().strftime("%Y%m%d")
            filename = f"{domain}_{timestamp}.txt"
            with open(filename, "w") as file:
                file.write("\n".join(subdomains))
            print(Fore.CYAN + f"\nSubdomains saved to {filename}")
        else:
            print(Fore.RED + f"Error fetching data from Findora (HTTP {response.status_code})")
    except Exception as e:
        print(Fore.RED + f"Error finding subdomains: {e}")

def findora_scan(target):
    try:
        print(Fore.CYAN + f"Scanning {target} with Findora...\n")
        nmap_command = f"nmap -p 1-1000 {target}"
        result = subprocess.run(nmap_command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            output = result.stdout.strip().split("\n")
            filtered_output = [line for line in output if "open" in line]
            if filtered_output:
                print(Fore.YELLOW + "\nActive Ports:")
                for line in filtered_output:
                    print(Fore.GREEN + line)
            else:
                print(Fore.RED + "No open ports found.")
        else:
            print(Fore.RED + "\nError during nmap scan.")
    except Exception as e:
        print(Fore.RED + f"Error occurred during Findora scan: {e}")

def validate_target(target):
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    domain_pattern = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
    return ip_pattern.match(target) or domain_pattern.match(target)

def main():
    while True:
        try:
            print_header()
            choice = get_choice()

            if choice == "1":
                domain = input(Fore.CYAN + "\nEnter the target domain (e.g., example.com): ").strip()
                if validate_target(domain):
                    get_dns_records(domain)
                    break  # Exit after DNS record fetch
                else:
                    print(Fore.RED + "Invalid domain!")
            elif choice == "2":
                domain = input(Fore.CYAN + "\nEnter the target domain (e.g., example.com): ").strip()
                if validate_target(domain):
                    find_subdomains(domain)
                    break  # Exit after subdomain finder
                else:
                    print(Fore.RED + "Invalid domain!")
            elif choice == "3":
                target = input(Fore.CYAN + "\nEnter the target domain or IP address: ").strip()
                if validate_target(target):
                    findora_scan(target)
                    break  # Exit after port scan
                else:
                    print(Fore.RED + "Invalid target!")
            else:
                print(Fore.RED + "Invalid choice. Please select 1, 2, or 3.")
        except KeyboardInterrupt:
            print(Fore.RED + "\nProgram interrupted by user. Exiting...")
            sys.exit(0)

if __name__ == "__main__":
    main()
