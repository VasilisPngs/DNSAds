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
    if all(p.isdigit() for p in line.split('.')):
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

def is_whitelisted(domain, whitelist_set):
    parts = domain.split('.')
    for i in range(len(parts)):
        if '.'.join(parts[i:]) in whitelist_set:
            return True
    return False

def compress_domains(domains_set):
    compressed = set()
    for d in sorted(domains_set, key=len):
        parts = d.split('.')
        if not any('.'.join(parts[i:]) in compressed for i in range(1, len(parts))):
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

final_list = sorted(compress_domains({d for d in domains if not is_whitelisted(d, whitelist)}))

with open("blocklist.txt", "w") as f:
    f.write('\n'.join(f"||{d}^" for d in final_list) + '\n')
