import dns.resolver

# Set the target domain and record type
target_domain = "google.com"
record_types = [ "A" , "AAAA" , "CNAME" , "MX" , "NS" , "SOA" , "TXT" ]
# Create a DNS resolver
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8']
for record_type in record_types:
    # Perform DNS lookup for the target domain and record type
    try :
        answers = resolver.query( target_domain , record_type)
    except dns.resolver.NoAnswer:
        continue
    # Print the DNS records found
    print(f"DNS records for { target_domain } ==> { record_type }:")

    for read_data in answers:
        print(f"{read_data}", '\n')