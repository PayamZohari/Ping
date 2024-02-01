import dns.resolver


def dns_resolve(destination_address, dns_server):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]

    try:
        response = resolver.resolve(destination_address)
        ip_address = response[0].address
        return ip_address
    except dns.resolver.NXDOMAIN:
        print("Error: Non-existent domain.")
        return None
    except dns.resolver.Timeout:
        print("Error: DNS resolution timed out.")
        return None
    except dns.resolver.NoNameservers:
        print("Error: No DNS servers available.")
        return None
