import socket
import threading

def scan_ports(host, timeout=1.0):
    services = {
        7: "Echo", 19: "CHARGEN", 20: "FTP-Data", 21: "FTP-Control", 
        22: "SSH", 23: "Telnet", 25: "SMTP", 43: "Whois", 53: "DNS", 
        67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP", 79: "Finger", 
        80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCBind", 
        119: "NNTP", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS", 
        138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 
        162: "SNMP-Trap", 179: "BGP", 194: "IRC", 389: "LDAP", 
        443: "HTTPS", 445: "Microsoft-DS (SMB)", 464: "Kerberos-SetPassword", 
        465: "SMTPS", 500: "ISAKMP/IKE", 513: "Rlogin", 514: "Syslog", 
        515: "LPD", 543: "Klogin", 544: "Kshell", 548: "AFP", 
        554: "RTSP", 587: "SMTP-Submission", 631: "IPP", 636: "LDAPS", 
        873: "Rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS-Proxy", 
        1194: "OpenVPN", 1241: "Nessus", 1352: "Lotus-Notes", 1433: "MS-SQL", 
        1434: "MS-SQL-Monitor", 1521: "Oracle-DB", 1701: "L2TP", 1723: "PPTP", 
        1812: "RADIUS-Auth", 1813: "RADIUS-Acct", 2049: "NFS", 2181: "ZooKeeper", 
        2375: "Docker-Plain", 2376: "Docker-TLS", 3128: "Squid-Proxy", 3268: "LDAP-GC", 
        3306: "MySQL", 3389: "RDP", 3690: "SVN", 4500: "IPsec-NAT-T", 
        4848: "GlassFish", 5000: "Docker-Registry", 5060: "SIP", 5061: "SIP-TLS", 
        5222: "XMPP-Client", 5353: "mDNS", 5432: "PostgreSQL", 5672: "AMQP (RabbitMQ)", 
        5900: "VNC", 5984: "CouchDB", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 
        6379: "Redis", 6443: "Kubernetes-API", 6667: "IRC", 7000: "Cassandra", 
        8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt", 
        9000: "SonarQube/PHP-FPM", 9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch-Nodes", 
        11211: "Memcached", 27017: "MongoDB", 50000: "SAP", 50070: "HDFS-NameNode"
    }

    def check_port(port, service_name):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) == 0:
                print(f"Port {port}: OPEN ({service_name})")
            else:
                print(f"Port {port}: CLOSE ({service_name})")

    threads = []
    for port, service_name in services.items():
        thread = threading.Thread(target=check_port, args=(port, service_name))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    host = input("[+] Enter host: ")
    scan_ports(host)
