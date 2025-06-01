import requests

# the domain to scan for subdomains
domain = "google.com"

file = open("subdomains.txt")
content = file.read()
subdomains = content.splitlines()

# a list of discovered subdomains
discovered_subdomains = []

for subdomain in subdomains :
# construct the url
    url = f"http://{subdomain}.{domain}"
    try:
        # if this raises an ERROR, that means the subdomain does not exist
        requests.get( url )

    except requests.ConnectionError:
    # if the subdomain does not exist, just pass, print nothing
        pass
    else:
        print("[✓] Discovered subdomain:" , url)