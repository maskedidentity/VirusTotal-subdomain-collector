import requests
import os
import sys
import time
VT_KEYS = ["enter key 1" ,"enter key 2", "enter key 3"]
VT_KEYS = [k for k in VT_KEYS if k]

if not VT_KEYS:
    print("Please set at least one VirusTotal API key (VT_KEY1 / VT_KEY2 / VT_KEY3).")
    sys.exit(1)

VT_URL = "https://www.virustotal.com/vtapi/v2/domain/report"
key_index = 0
domain_input = None
file_input = None

args = sys.argv[1:]
i = 0
while i < len(args):
    if args[i] == "-d" and i + 1 < len(args):
        domain_input = args[i + 1]
        i += 2
    elif args[i] == "-l" and i + 1 < len(args):
        file_input = args[i + 1]
        i += 2
    else:
        print(f"Unknown flag or missing value: {args[i]}")
        sys.exit(1)

if not domain_input and not file_input:
    print("Usage: python vt_recursive_subdomains_flags.py -d <domain> -l <subdomains_file.txt>")
    sys.exit(1)

def get_subdomains(domain):
    global key_index
    apikey = VT_KEYS[key_index]
    key_index += 1
    if key_index >= len(VT_KEYS):
        key_index = 0

    try:
        resp = requests.get(VT_URL, params={"apikey": apikey, "domain": domain}, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return data.get("subdomains", [])
    except Exception as e:
        print(f"Error fetching {domain}: {e}")
        return []


def recursive_enumeration(initial_domains):
    all_domains = set(initial_domains)
    queue = list(initial_domains)

    while queue:
        current = queue.pop(0)
        print(f"🔍 Checking subdomains of: {current}")

        subdomains = get_subdomains(current)
        new_subs = [s for s in subdomains if s not in all_domains]

        if new_subs:
            print(f"  ➕ Found {len(new_subs)} new subdomains under {current}")

        for s in new_subs:
            all_domains.add(s)
            queue.append(s)


        time.sleep(5)

    return list(all_domains)


initial_domains = []

if domain_input:
    initial_domains.append(domain_input)

if file_input:
    try:
        with open(file_input, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    initial_domains.append(line)
        print(f"Loaded {len(initial_domains) - (1 if domain_input else 0)} subdomains from {file_input}")
    except Exception as e:
        print(f"Could not read file {file_input}: {e}")
        sys.exit(1)

initial_domains = list(set(initial_domains))


result = recursive_enumeration(initial_domains)


print("\n=== All discovered domains ===")
for r in sorted(result):
    print(r)

print(f"\nTotal: {len(result)} domains found.")
