import whois
from domain_validation import is_registered

if is_registered("google.com") == True:
    whois_info = whois.whois("facebook.com")
# print the registrar
    print ( "Domain registrar:" , whois_info.registrar)
# print the WHOIS server
    print ( "WHOIS server:" , whois_info.whois_server)
# get the creation time
    print ( "Domain creation date:" , whois_info.creation_date)
# get the update time
    print ( "Domain updated date:" , whois_info.updated_date)
# get expiration date
    print ( "Expiration date:" , whois_info.expiration_date)
# get all emails
    print("all emails:", whois_info.emails)
