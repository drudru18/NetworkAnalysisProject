import pyshark
import dns.resolver
import json


# get the dns servers used and stock them into the file

def get_dns_servers(pcap_file):

    # Dictionary to store DNS servers with their information
    dns_servers = {}

    # Open pcap file
    with pyshark.FileCapture(pcap_file, 'r') as cap:
        for packet in cap:
            try:
                if packet.dns.qry_name:
                    dns_server = packet.dns.qry_name
                    # dns_ip = packet.ip.src
                    # ip_version = "IPv4" if ":" not in dns_ip else "IPv6"

                    # Check if DNS server already exists in the dictionary
                    if dns_server not in dns_servers:
                        # If not, initialize the entry with an empty list of authoritative DNS servers
                        dns_servers[dns_server] = {"Main domains": {}}
                    
                    # Add the IP protocol (here, most of the time, it will be IPv4)
                    # dns_servers[dns_server]["IP Protocol"] = ip_version

                    # Add the authoritative DNS server if it's not already in the list
                    auth_serv = get_authoritative_nameserver(dns_server)
                    if auth_serv not in dns_servers[dns_server]["Main domains"].items():
                        dns_servers[dns_server]["Main domains"] = auth_serv
            except AttributeError:
                pass
    
    # Write the data to a json file
    with open('.\\dns_servers.json', 'w') as file:
        json.dump(dns_servers, file, indent=4)

    return dns_servers




# get autoriative dns servers for the dns servers

def get_authoritative_nameserver(domain):
    server_list = []
    to_check = None
    cname_dns(domain, server_list)

    if server_list == []:
        to_check = domain
    else:
        # ici on prend le dernier élément de la liste, qui est le nom de domaine final
        # et on va chercher les serveurs administratifs pour ce nom de domaine
        to_check = server_list[-1]

    try:
        servers = dns.resolver.resolve(to_check, rdtype='NS')
        for server in servers:
            server_list.append(str(server))
    except dns.resolver.NoAnswer:
        pass

    """
    le code ici est pour enlever le www. ou autre préfixe du nom de domaine pour obtenir 
    le nom de domaine final si jamais la liste est tojours vide ou qu'on n'a pas atteint le nom de domaine final
    """
    #if server_list == []:
    final_str = ""
    res = domain.split(".")
    for i in range(len(res[1:])):
        final_str += res[i+1] + "."
    ns_dns(final_str[:-1], server_list)
    

    return server_list

# ici la fonction va chercher récursivement des alias pour un nom de domaine donné

def cname_dns(domain, liste):
    try:
        servers = dns.resolver.resolve(domain, rdtype='CNAME')
        for server in servers:
            liste.append(str(server))
            cname_dns(str(server), liste)
    except dns.resolver.NoAnswer:
        pass
    return liste

# ici la fonction va chercher récursivement les serveurs administratifs pour un nom de domaine donné

def ns_dns(domain, liste):
    try:
        servers = dns.resolver.resolve(domain, rdtype='NS')
        for server in servers:
            if server not in liste:
                liste.append(str(server))
            #ns_dns(str(server), liste)
    except dns.resolver.NoAnswer:
        pass
    return liste



if __name__ == '__main__':
    pass
    
    # uncomment the lines below to run the functions (and comment the pass statement above)
    #get_dns_servers(pcap_file='.\\icloud-pkg.pcapng')