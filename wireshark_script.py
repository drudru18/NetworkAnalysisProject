import pyshark
import dns.resolver
import json

"""
    AFIN DE FAIRE TOURNER LE SCRIPT, VEUILLEZ LIRE LA CONDITION if __name__=='__main__': SE TROUVANT EN BAS DU SCRIPT
    L'EXÉCUTION DU SCRIPT PRENDRA DU TEMPS, ENVIRON 1-2 MINUTES
    
    !! VEUILLEZ EFFACER LE CONTENU DU FICHIER dns_servers.json AVANT DE FAIRE TOURNER LE SCRIPT
"""



# cette fonction crée un dictionnaire dans le fichier dns_servers.json avec tous les serveurs dns trouvés dans la
# capture de paquets et également les serveurs alias et les serveurs autoritatifs

def get_dns_servers(pcap_file):

    # dico pour insérer les serveurs
    dns_servers = {}

    # on ouvre le fichier pcap
    with pyshark.FileCapture(pcap_file, 'r') as cap:
        for packet in cap:
            try:
                if packet.dns.qry_name:
                    dns_server = packet.dns.qry_name

                    # on regarde si le serveur existe déjà dans le dico
                    if dns_server not in dns_servers:
                        # si non, on crée un sous dictionnaire à se serveur avec les serveurs alias et autoritatifs
                        dns_servers[dns_server] = {"Main domains": {}}

                    # ici on ajoute le serveur autoritatif si celui-ci ne se trouve pas déjà dans le dictionnaire
                    auth_serv = get_authoritative_nameserver(dns_server)
                    if auth_serv not in dns_servers[dns_server]["Main domains"].items():
                        dns_servers[dns_server]["Main domains"] = auth_serv
            except AttributeError:
                pass
    
    # et finalement on écrit le dictionnaire dans le fichier json
    with open('.\\dns_servers.json', 'w') as file:
        json.dump(dns_servers, file, indent=4)

    return dns_servers




# on prend les serveurs autoritatifs du serveur dns donné (ou alias)

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
    except dns.resolver.NoAnswer:
        pass
    return liste



if __name__ == '__main__':
    pass
    
    # le fichier qui est déjà comme argument est le fichier avec la capture Ethernet
    # enlevez le 'pass' au-dessus afin de faire tourner le script
    # enlevez le commentaire de la ligne en dessous afin de faire tourner le script
    
    # get_dns_servers(pcap_file='.\\icloud-pkg.pcapng')
