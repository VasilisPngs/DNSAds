import urllib.request

SOURCES = [
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers.txt",
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers_firstparty.txt",
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/foreign.txt",
    "https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/rules.txt",
    "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt",
    "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt",
    "https://www.void.gr/kargig/void-gr-filters.txt"
]

EXCLUSIONS = [
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt"
]

BROAD_DOMAIN_SAFELIST = {
    "amazonaws.com", "googleapis.com", "cloudfront.net", "akamaized.net",
    "fastly.net", "gstatic.com", "github.com", "github.io",
    "cloudflare.com", "azureedge.net"
}

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

def is_whitelisted(domain, whitelist_set):
    parts = domain.split('.')
    for i in range(len(parts)):
        parent = '.'.join(parts[i:])
        if parent in whitelist_set:
            return True
    return False

def compress_domains(domains_set):
    sorted_domains = sorted(list(domains_set), key=len)
    compressed = set()
    for d in sorted_domains:
        if d in BROAD_DOMAIN_SAFELIST:
            continue
        parts = d.split('.')
        is_subdomain = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in compressed and parent not in BROAD_DOMAIN_SAFELIST:
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

raw_list = {d for d in domains if not is_whitelisted(d, whitelist)}
final_list = sorted(list(compress_domains(raw_list)))

with open("blocklist.txt", "w") as f:
    for d in final_list:
        f.write(f"||{d}^\n")
