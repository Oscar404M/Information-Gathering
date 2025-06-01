import whois

def is_registered( domainName ):
    try :
        check = whois.whois(domainName)
    except Exception :
        return False
    else :
        return bool(check.domain_name)

domain_names = [
    "google.com",
    "github.com",
    "whatafakewebsite.com",
    "hostit.co",
    "tryhackme.com",
    "mega.com"
]
if __name__ == '__main__':
    for domain in domain_names:
        if is_registered(domain) == True:
            print(domain, "[✓] is registered")
        else:
            print(domain, "[X] not registered")
