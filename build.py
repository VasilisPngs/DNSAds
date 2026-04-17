import urllib.request
import re

SOURCES = [
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers.txt",
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers_firstparty.txt",
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/foreign.txt",
    "https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt",
    "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt"
]

EXCLUSIONS = "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt"
EXCEPTIONS = "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt"

def fetch_data(url):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as response:
        return response.read().decode('utf-8').splitlines()

def extract_domain(line):
    line = line.strip()
    
    if not line or line.startswith('!') or line.startswith('#') or '##' in line or '#?#' in line:
        return None
        
    if line.startswith('||'):
        line = line[2:]
    elif line.startswith('|'):
        return None
        
    line = line.split('$')[0]
    line = line.strip('^')
    
    if '/' in line or '*' in line or ':' in line or '=' in line or '?' in line:
        return None
        
    if '.' not in line or ' ' in line:
        return None
        
    line = line.lstrip('.')
        
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
