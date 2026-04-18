import urllib.request

SOURCES = [
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers.txt",
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers_firstparty.txt",
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/foreign.txt",
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/cryptominers.txt",
    "https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/adservers.txt",
    "https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers.txt",
    "https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers_firstparty.txt",
    "https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/mobile.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/rules.txt",
    "https://www.void.gr/kargig/void-gr-filters.txt"
]

EXCLUSIONS = [
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt"
]

INVALID_CHARS = set("/*:=? ")

def fetch_data(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as response:
        return response.read().decode('utf-8').splitlines()

def extract_domain(line):
    line = line.strip()
    if not line or '#' in line or not line.startswith('||'):
        return None
    line = line[2:].split('$')[0].strip('^')
    if not INVALID_CHARS.isdisjoint(line) or '.' not in line:
        return None
    line = line.lstrip('.')
    if line.replace('.', '').isdigit():
        return None
    return line

def extract_whitelist_domain(line):
    line = line.strip()
    if not line or line.startswith(('!', '#')) or '#' in line:
        return None
    if line.startswith('@@||'):
        line = line[4:]
    elif line.startswith('@@'):
        line = line[2:]
    elif line.startswith('||'):
        line = line[2:]
    else:
        return None
    line = line.split('$')[0].strip('^')
    if not INVALID_CHARS.isdisjoint(line) or '.' not in line:
        return None
    return line.lstrip('.')

def is_whitelisted(domain, whitelist_set):
    if domain in whitelist_set:
        return True
    idx = domain.find('.')
    while idx != -1:
        if domain[idx+1:] in whitelist_set:
            return True
        idx = domain.find('.', idx+1)
    return False

def compress_domains(domains_set):
    compressed = set()
    for d in sorted(domains_set, key=len):
        idx = d.find('.')
        is_sub = False
        while idx != -1:
            if d[idx+1:] in compressed:
                is_sub = True
                break
            idx = d.find('.', idx+1)
        if not is_sub:
            compressed.add(d)
    return compressed

domains = set()
for url in SOURCES:
    try:
        domains.update(filter(None, map(extract_domain, fetch_data(url))))
    except:
        pass

whitelist = set()
for url in EXCLUSIONS:
    try:
        whitelist.update(filter(None, map(extract_whitelist_domain, fetch_data(url))))
    except:
        pass

final_list = sorted(compress_domains({d for d in domains if not is_whitelisted(d, whitelist)}))

with open("blocklist.txt", "w") as f:
    f.write('\n'.join(f"||{d}^" for d in final_list) + '\n')
