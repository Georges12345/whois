import argparse
import subprocess
from tabulate import tabulate
from colorama import Fore, Style

def whois_lookup(domain):
    try:
        # Run the 'whois' command using subprocess
        output = subprocess.check_output(['whois', domain]).decode('utf-8')
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return None

def extract_useful_info(data):
    useful_info = []
    lines = data.splitlines()

    for line in lines:
        line = line.strip()
        if line.startswith(('Domain Name:', 'Registrar:', 'Updated Date:', 'Creation Date:', 'Expiration Date:', 'Registrant', 'Admin', 'Tech')):
            field, value = line.split(':', 1)
            if 'Registrant' in field:
                field = Fore.BLUE + field + Style.RESET_ALL
            elif 'Admin' in field:
                field = Fore.YELLOW + field + Style.RESET_ALL
            elif 'Tech' in field:
                field = Fore.CYAN + field + Style.RESET_ALL
            else:
                field = Fore.WHITE + field + Style.RESET_ALL
            value = value.strip()
            if not value:
                value = Fore.RED + 'not found' + Style.RESET_ALL
            else:
                value = Fore.GREEN + value + Style.RESET_ALL
            useful_info.append([field, value])

    # Check if any expected fields are missing
    expected_fields = ['Domain Name', 'Registrar', 'Updated Date', 'Creation Date', 'Expiration Date', 'Registrant', 'Admin', 'Tech']
    for field in expected_fields:
        found = False
        for info in useful_info:
            if field in info[0]:
                found = True
                break
        if not found:
            useful_info.append([Fore.RED + field + Style.RESET_ALL, Fore.RED + 'not found' + Style.RESET_ALL])

    return useful_info

# Parse command-line arguments
parser = argparse.ArgumentParser(description='WHOIS Lookup Script')
parser.add_argument('domain', help='Domain name to perform WHOIS lookup')
args = parser.parse_args()

# Perform WHOIS lookup
whois_data = whois_lookup(args.domain)

if whois_data:
    useful_info = extract_useful_info(whois_data)
    table = tabulate(useful_info, headers=['Field', 'Value'], tablefmt='grid')
    print(f"Useful information for {args.domain}:\n{table}")
else:
    print(f"Failed to retrieve WHOIS data for {args.domain}")
