import pyshark
import dns.resolver
import json

"""
###############################################################################################
                            ##    ##    #   ####
                            # #   # #   #   #
                            #  #  #  #  #   ####
                            # #   #   # #      #
                            ##    #    ##   ####
###############################################################################################
"""

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



""" 
    based on our pcapng file, we can see that the dns servers used are (expand the arrow or look in the dns_servers.json file):
"""
"""
{
    www.icloud.com
    e4478.dscb.akamaiedge.net
    www.google.com
    www.apple.com
    e6858.dscx.akamaiedge.net
    incoming.telemetry.mozilla.org
    gateway.icloud.com
    ckdatabasews.icloud.com
    cvws.icloud-content.com
    setup.icloud.com
    telemetry-incoming.r53-2.services.mozilla.com
    gateway.fe2.apple-dns.net
    ckdatabasews.fe2.apple-dns.net
    cvws.apple-dns.net
    setup.fe2.apple-dns.net
    appleid.cdn-apple.com
    p34-mailws.icloud.com
    p34-docws.icloud.com
    p34-ckdatabasews.icloud.com
    p34-keyvalueservice.icloud.com
    e2885.e9.akamaiedge.net
    mr-mailws.icloud.com.akadns.net
    docws.fe2.apple-dns.net
    keyvalueservice.fe2.apple-dns.net
    p34-setup.icloud.com
    p34-contactsws.icloud.com
    p34-calendarws.icloud.com
    p34-remindersws.icloud.com
    experiments.apple.com
    gatewayws.icloud.com
    contactsws.fe2.apple-dns.net
    calendarws.fe2.apple-dns.net
    p34-mccgateway.icloud.com
    remindersws.fe2.apple-dns.net
    e3925.dscg.akamaiedge.net
    ocsp.apple.com
    gatewayws.fe2.apple-dns.net
    mccgateway.fe2.apple-dns.net
    ocsp-a.g.aaplimg.com
    p34-pushws.icloud.com
    pushws.fe2.apple-dns.net
    p34-ckdevice.icloud.com
    ckdevice.fe2.apple-dns.net
    webcourier.push.apple.com
    webcourier-vs.push-apple.com.akadns.net
    cvws-001.icloud-content.com
    cvws-002.icloud-content.com
    cvws-003.icloud-content.com
    cdn.apple-cloudkit.com
    cvws-001.cvws.apple-dns.net
    cvws-002.cvws.apple-dns.net
    e9335.b.akamaiedge.net
    cvws-003.cvws.apple-dns.net
    feedbackws.icloud.com
    feedbackws.fe2.apple-dns.net
    safebrowsing.googleapis.com
    self.events.data.microsoft.com
    www.google.com.420352670881483.windows-display-service.com
}
"""
"""
    which totals to 58 unique dns servers
"""

# Q: Combien de noms de domaines sont résolus et quand ?

# A: Ici nous avons compté 58 noms de domaines uniques qui sont résolus que lorsqu'une requête DNS est envoyée à un serveur DNS pour obtenir l'adresse IP associée à un nom de domaine. 
#    Dans ce cas-ci, comme nous utilisons un cloud, la requête DNS est associée au fait que nous voulons accéder à des donnéeés stockées dans un serveur.



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

# ici la fonction va chercher récursivement les serveurs administratifs pour un nom de domaine donné

def cname_dns(domain, liste):
    try:
        servers = dns.resolver.resolve(domain, rdtype='CNAME')
        for server in servers:
            liste.append(str(server))
            cname_dns(str(server), liste)
    except dns.resolver.NoAnswer:
        pass
    return liste

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

    
# Q: Quels sont les serveurs autoritatifs pour ces noms de domaines ?

# A: Nous pouvons voir ci-dessous quelques serveurs administratifs pour certains noms de domaines et nous pouvons remarquer que certains 
#    noms de domaines ont plusieurs serveurs administratifs, parfois les mêmes pour certains noms de domaines. (tous les autres serveurs se trouvent
#    dans le fichier dns_servers.json)
#    Nous avons aussi constaté que pour certains noms de domaines (ceux ayant le www. comme préfixe), si on leur enlève ce préfixe et qu'on cherche leurs
#    serveurs administratifs, on obtient des résultats différents.


"""
    Authoritative name servers for www.google.com.420352670881483.windows-display-service.com:
        -> ns2.nameserverservice.com.
        -> ns1.nameserverservice.com.

    Authoritative name servers for cvws.apple-dns.net:
        -> ns-747.awsdns-29.net.
        -> ns-1156.awsdns-16.org.
        -> ns-1651.awsdns-14.co.uk.
        -> ns-303.awsdns-37.com.

    Authoritative name servers for cvws.icloud-content.com:
        -> ns-747.awsdns-29.net.
        -> ns-1156.awsdns-16.org.
        -> ns-1651.awsdns-14.co.uk.
        -> ns-303.awsdns-37.com.
"""


# Q: À quelles entreprises appartiennent les noms de domaines résolus ? Il y en a-t-il d’autres que celle qui détient l’application ?

# A: Certains noms de domaines administratifs proviennent des serverus Amazon Web Services, comme dans le cas de cvws.apple-dns.net et cvws.icloud-content.com,
#    serveurs qui n'appartiennt pas directement à Apple mais qui sont utilisés pour stocker des données.
    


# Q: Quels sont les types de requête DNS effectuées ?

# A: Les types de requêtes DNS effectuées sont principalement des requêtes de type A, qui sont des requêtes de résolution de nom de domaine en adresse IP.
#    Il y a aussi des requêtes de type AAAA qui sont des requêtes de résolution de nom de domaine en adresse IPv6.



# Q: Lorsqu’une requête DNS souhaite obtenir une adresse IP, quelle est sa famille ? 
#    Il y a-t-il une version IP préférée par l’application ?

# A: Lorsqu'on se connecte sur icloud, on peut remarquer que le nombre de requêtes DNS de type A est approximativement équivalent à celui de type AAAA. (voir onglet 'statistiques -> DNS' dans wireshark)
#    Ceci est du au fait que l'application utilise les deux versions d'IP, IPv4 et IPv6, ce qui peut empêcher des problèmes de compatibilité avec certains serveurs. (Happy Eyeballs)
#    Si jamais l'adresse IPv4 venait à ne pas fonctionner, l'application pourrait utiliser l'adresse IPv6 et vice-versa. 
#    L'application essaye de donner priorité à l'adresse IPv6, mais si elle n'est pas disponible, elle utilise l'adresse IPv4.



# Q: Les requêtes contiennent elles des records additionnels ? Le cas échéant, à quoi servent-ils ?

# A: Autre que A ou AAAA, les requêtes DNS contiennent des records additionnels, comme des records de type CNAME (canonical name), qui sont des alias pour un nom de domaine donné.
#    Ces records additionnels servent à rediriger une requête DNS vers un autre nom de domaine, qui peut être le nom de domaine final ou un autre alias.



# Q: Observez-vous des comportements DNS inattendus ?

# A: Nous n'avons pas observé de comportements DNS inattendus, mais nous avons pu observer que certains noms de domaines ont plusieurs serveurs administratifs, parfois les mêmes pour certains noms de domaines. (voir fichier dns_servers.json)



# Q: Lorsque IPv4 est utilisé, l’application utilise-t-elle des techniques pour traverser les NAT ?

# A: Oui, l'application utilise NAT pour transférer les paquets du serveur vers mon ordinateur, et elle fait ceci en transformant mon adresse IPv4 privée en une adresse publique (qui elle est communiquée au serveur)
#    Ceci est possible grâce au routeur qui se trouve entre mon ordinateur et le serveur, qui va traduire l'adresse privée en adresse publique et vice-versa.



# Q: Quels sont les adresses vers lesquels des paquets sont envoyés ? 
#    Retrouvez à quels noms de domaine elles correspondent, observez-vous une tendance particulière dans la famille d’adresse ? 
#    Pouvez-vous l’expliquer ?

# A: Les adresses vers lesquelles des paquets sont envoyés sont principalement icloud.com sous la forme des adresses IPv6 vu que icloud donne priorité au IPv6, mais également apple.com et google.com.
#    Les noms des domaines de icloud.com et apple.com appartiennt à Apple, tandis que google.com appartient à Google. Par exemple, les noms des domaines de Apple et iCloud commencent par <lettre>.ns.apple.com. et ceux de google par ns<chiffre>.google.com.
#    On peut remarquer que dans les cas d'Apple, iCloud et Google, leurs serveurs administratifs contiennent le préfixe 'ns' suivi du nom de domaine de l'entreprise, ce qui peut indiquer que ces entreprises utilisent leurs propres serveurs pour stocker des données.
#    Apple utilise également des serverus proveenant d'Amazon (AWS, Amazon Web Services) mais également ceux de Microsoft (Azure) et sur base de cet article (mettre lien bas de page == https://www.turningcloud.com/blog/apple-uses-aws/) depuis 2016, Apple utiliserait également 
#    des serveurs provenant de Google, d'où l'apparition du domaine de Google dans les paquets. Si nous prenons par exemple ce nom de domaine 'cvws.apple-dns.net', nous pouvons voir que le serveur administratif est un serveur Amazon Web Services même si dans le nom nous avons le mot 'apple'.



# Q: Quels sont les protocoles de transports utilisés pour chaque fonctionnalité ?

# A: Pour transférer des données, on utilise généralement TCP mais dans le cas de iCloud, pour avoir un transfert sans interruptions, Apple utilise le protocole QUIC, qui permet de transférer des données sous forme de stream, comme ça si un fichier transféré par TCP venait à donner une 
#    erreur, le transfert serait interrompu et il faudrait recommencer depuis le début, tandis qu'avec QUIC, si un fichier parmi tous ceux se trouvant dans le stream venait à donner une erreur, le transfert continue mais ne recommence le transfert que du fichier corrompu. 
#    QUIC est un protocole de transport qui est basé sur UDP et qui est plus performant que TCP.
#    Pour la communication entre serveurs et le chargement des pages, HTTP2 et HTTP3 sont utilisés.
#    Pour la sécurité des données, comme son nom l'indique, TLSv1.2 et TLSv1.3 (Transport Security Layer) sont utilisés.
#    Dans les extensions de TLS nous trouvons égalament le protocole ALPN h2 (Application-Layer Protocol Negotiation) qui permet de négocier le protocole de transport à utiliser pour la communication entre le client et le serveur lors d'un handshake. Le 'h2' indique que le protocole HTTP2 est utilisé.
#    En décryptant les paquets TLS, on tombe sur du HTTP.



# Q: Il y a-t-il plusieurs connexions vers un même nom de domaine ? Si oui, pouvez-vous l’expliquer ?

# A: Oui, il existe plusieurs connexions vers un même nom de domaine, et ceci est du au fait que l'application utilise plusieurs serveurs pour stocker des données, et pour éviter une surcharge sur un seul serveur, l'application utilise plusieurs connexions vers un même nom de domaine.
#    Si jamais un serveur venait à ne pas fonctionner, l'application peut toujours accéder à l'autre serveur disponible pour obtenir les informations que le client demande.
#    C'est pour cela que un nom de domaine doit posséder au minimum deux serveurs administratifs pour éviter le plantage du serveur.



# Q: Si vous observez du trafic QUIC, quels sont les versions utilisées ? Pouvez-vous identifier des extensions négociées dans le handshake ?

# A: Oui, iCloud utilise le protocole QUIC IETF, avec la version 1 (0x00000001). Dans le handshake, on peut apercevoir l'extension avec le nom du serveur, l'extension ALPN h3, qui est utilisée pour négocier le protocole de transport à utiliser pour la communication entre le client et le serveur 
#    (ceci se faisant sur base de HTTP3, d'où le h3 après ALPN) et également les paramètres de transport de QUIC.



# Q: Lorsque vous observez du trafic UDP, identifiez-vous d’autres protocoles que QUIC et DNS ? 
#    Expliquez comment ils sont utilisés par l’application.

# A: Autre que QUIC, DNS et HTTP3, le protocole SSDP (Simple Service Discovery Protocol) est utilisé pour découvrir des services disponibles sur un réseau local. Cela permet aux appareils de s'alerter mutuellement de leur présence sur le réseau et de partager des informations sur les services qu'ils offrent.



# Q: L’utilisation du DNS est-elle sécurisée ? Comment ?

# A: L'utlisation du DNS en soi n'est pas très sécurisée sachant que c'est un protocole qui ne vérifie pas l'idéntité de l'utilisateur. TLS de l'autre côté est un protocole où les données sont chiffrées mais qui peuvent être déchiffreés grâce à une clé SSL générée par le navigateur.



# Q: Quelles versions de TLS sont utilisées ? Précisez les protocoles de transport sécurisés par ces versions.

# A: Lors des Client Hello, nous pouvons aperceveoir dans les extensions les versions de TLS utilisées par iCloud, qui sont les versions 1.2 et 1.3.
#    Généralement, TLS est construit au-dessus de TCP, encryptant les données de l'application (si on ne décrypte pas les paquets, nous pouvons apercevoir un 'Application Data' dans l'information du packet). Le TLS encrypte vraiment le payload du packet et ceci ne peut être décryptable. En décryptant le reste du packet, la plupart du temps on tombe sur du HTTP2 ou HTTP3.



# Q: Quel est la durée de vie des certificats utilisés ? Par qui sont-ils certifiés ?

# A: La durée de vie des certificats TLS utilisés est de 13 mois environ (en tapant la commande tls.handshake.type==11 dans la barre des filtres on peut trouver les packets qui ont des certificats). Les paquets sont certifiés par Apple Inc, Microsoft Azure ou DigiCert Inc.



# Q: Lorsque vous pouvez observer l’établissement du chiffrement, quels sont les algorithmes de chiffrement utilisés ?

# A: Le chiffrement des certificats fournis par Apple se fait en utilisant l'algorithme sha256WithRSAEncryption. Pour les certificats fournis par Microsoft Azure et DigiCert Inc, ceux-ci utilisent l'algorithme sha384WithRSAEncryption pour l'encryption. Pour le 'Certificate Verify', l'algorithme utilisé est ecdsa_secp256r1_sha256 tandis que pour le 'Server Key Exchange', on utilise l'algorithme rsa_pss_rsae_sha256. On aperçoit églement une autre organisation nomée Comod CA Limited qui elle aussi fournit des certificats encryptés par le même algorithme que Apple utilise.



# Q: Si vous observez du trafic UDP, semble-t-il chiffré ? Comment est-il sécurisé ?

# A: Le seul trafic UDP qui est cncrypté est celui utilisé par le protocole QUIC/HTTP3 puisque celui-ci utilise TLS pour encrypter ses données. DNS lui, n'est pas sécurisé. Pour le protocole QUIC, dans le premier paquet QUIC détecté, nous pouvons voir dans le handshake protocol, (dans la partie CRYPTO du packet), une section 'Cipher Suite' qui contient 3 algorithmes de hashage des données: TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256 et TLS_AES_256_GCM_SHA384. Nous pouvons constater que c'est bien TLS qui encrypte les données. Ce sont les 3 algorithmes utilisés par défaut. (d'après https://wiki.openssl.org/index.php/TLS1.3 (note de bas de page))


if __name__ == '__main__':
    pass
    
    # uncomment the lines below to run the functions (and comment the pass statement above)
    #get_dns_servers(pcap_file='.\\icloud-pkg.pcapng')