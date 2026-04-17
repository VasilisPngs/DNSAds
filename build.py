import urllib.request
import re

SOURCES = [
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers.txt",
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers_firstparty.txt",
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/foreign.txt",
    "https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/adservers.txt"
]

EXCLUSIONS = "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt"
EXCEPTIONS = "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt"

def fetch_data(url):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as response:
        return response.read().decode('utf-8').splitlines()

def extract_domain(line):
    line = line.strip()
    if not line or line.startswith('!') or line.startswith('#'):
        return None
    line = re.sub(r'\$.*', '', line)
    line = re.sub(r'\^.*', '', line)
    line = line.replace('||', '').replace('|', '')
    if '/' in line or '*' in line or '=' in line:
        return None
    return line

domains = set()
for url in SOURCES:
    try:
        for line in fetch_data(url):
            domain = extract_domain(line)
            if domain:
                domains.add(domain)
    except:
        pass

whitelist = set()
for url in [EXCLUSIONS, EXCEPTIONS]:
    try:
        for line in fetch_data(url):
            domain = extract_domain(line)
            if domain:
                whitelist.add(domain)
    except:
        pass

final_list = sorted(list(domains - whitelist))

with open("blocklist.txt", "w") as f:
    for d in final_list:
        f.write(f"||{d}^\n")
