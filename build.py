import urllib.request

SOURCES = [
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers.txt",
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers_firstparty.txt",
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/foreign.txt",
    "https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/rules.txt",
    "https://www.void.gr/kargig/void-gr-filters.txt"
]

EXCLUSIONS = [
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt"
]

def fetch_data(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as response:
        return response.read().decode('utf-8').splitlines()

def extract_domain(line):
    line = line.strip()
    if not line or line.startswith('!') or line.startswith('#') or line.startswith('@@'):
        return None
    if '#' in line:
        return None
    if not line.startswith('||'):
        return None
    line = line[2:]
    line = line.split('$')[0]
    line = line.strip('^')
    if '/' in line or '*' in line or ':' in line or '=' in line or '?' in line or ' ' in line:
        return None
    if '.' not in line:
        return None
    line = line.lstrip('.')
    parts = line.split('.')
    if all(part.isdigit() for part in parts):
        return None
    return line

def extract_whitelist_domain(line):
    line = line.strip()
    if not line or line.startswith('!') or line.startswith('#'):
        return None
    if line.startswith('@@||'):
        line = line[4:]
    elif line.startswith('@@'):
        line = line[2:]
    elif line.startswith('||'):
        line = line[2:]
    else:
        return None
    if '#' in line:
        return None
    line = line.split('$')[0]
    line = line.strip('^')
    if '/' in line or '*' in line or ':' in line or '=' in line or '?' in line or ' ' in line:
        return None
    if '.' not in line:
        return None
    return line.lstrip('.')

def compress_domains(domains_set):
    sorted_domains = sorted(list(domains_set), key=len)
    compressed = set()
    for d in sorted_domains:
        parts = d.split('.')
        is_subdomain = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in compressed:
                is_subdomain = True
                break
        if not is_subdomain:
            compressed.add(d)
    return compressed

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
for url in EXCLUSIONS:
    try:
        for line in fetch_data(url):
            domain = extract_whitelist_domain(line)
            if domain:
                whitelist.add(domain)
    except:
        pass

raw_list = domains - whitelist
final_compressed = compress_domains(raw_list)
final_list = sorted(list(final_compressed))

with open("blocklist.txt", "w") as f:
    for d in final_list:
        f.write(f"||{d}^\n")
