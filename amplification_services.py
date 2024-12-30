import subprocess
import shutil
import sys
import ipaddress
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("scan.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

VERMELHO = "\033[0;31m"
VERDE = "\033[0;32m"
SEMCOR = "\033[0m"

PROGRAMAS = [
    "host", "nmap", "nmblookup", "nc", "rpcinfo", "curl",
    "dig", "snmpget", "ntpq", "ldapsearch", "hexdump"
]

resultados = {}

default_timeout = 5
default_threads = 50
default_progress = True

def verificar_programas():
    """Verifica se todos os programas necessários estão instalados."""
    for programa in PROGRAMAS:
        if not shutil.which(programa):
            logging.error(f"Não tem instalado o programa {programa}!")
            sys.exit(1)

def executar_comando(comando):
    """Executa um comando no shell e retorna a saída."""
    try:
        resultado = subprocess.run(
            comando, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=default_timeout
        )
        return resultado.stdout.strip()
    except subprocess.TimeoutExpired:
        logging.warning(f"Timeout ao executar comando: {comando}")
        return ""
    except Exception as e:
        logging.error(f"Erro ao executar comando: {comando}\n{e}")
        return ""

def testar_porta(teste_nome, ip, comando, condicao):
    """Executa o teste de uma porta específica e registra o resultado."""
    saida = executar_comando(comando)
    if saida == "":
        logging.info(f"{ip} - Testando {teste_nome}: {VERDE}Erro ou Timeout{SEMCOR}")
        return 
    if condicao(saida):
        logging.warning(f"{ip} - Testando {teste_nome}: {VERMELHO}Aberta{SEMCOR}")
        if ip not in resultados:
            resultados[ip] = []
        resultados[ip].append(teste_nome)
    else:
        logging.info(f"{ip} - Testando {teste_nome}: {VERDE}Fechada{SEMCOR}")

def netbios(ip): testar_porta("NETBIOS (137/udp)", ip, f"nmblookup -A {ip}", lambda x: "No reply from" not in x)
def dhcpdiscover(ip): testar_porta("DVR-DHCPDiscover (37810/udp)", ip, f"echo -n '\\xff' | nc -w 3 -u {ip} 37810 | hexdump -C", bool)
def rpc(ip): testar_porta("RPC (111/udp)", ip, f"rpcinfo -T udp -p {ip}", bool)
def arms(ip): testar_porta("ARMS (3283/udp)", ip, f"printf '\\x00\\x14\\x00\\x01\\x03' | nc -w 3 -u {ip} 3283 | hexdump -C", bool)
def tftp(ip): testar_porta("TFTP (69/udp)", ip, f"curl -m 3 tftp://{ip}/a.pdf", lambda x: "Operation timed" not in x and "Connection refused" not in x)
def dns(ip): testar_porta("DNS (53/udp)", ip, f"host -W 5 google.com {ip}", lambda x: "timed out" not in x and "SERVFAIL" not in x and "refused" not in x and "no servers could be reached" not in x)
def mdns(ip): testar_porta("Multicast DNS (5353/udp)", ip, f"dig +timeout=1 @{ip} -p 5353 ptr _services._dns-sd._udp.local", lambda x: "no servers could be reached" not in x and "timed out" not in x and "connection refused" not in x)
def ssdp(ip): testar_porta("SSDP (1900/udp)", ip, f"printf 'M-SEARCH * HTTP/1.1\\r\\nHost:239.255.255.250:1900\\r\\nST:upnp:rootdevice\\r\\nMan:\"ssdp:discover\"\\r\\nMX:3\\r\\n\\r\\n' | nc -w 3 -u {ip} 1900 | hexdump -C", bool)
def snmp(ip): testar_porta("SNMP (161/udp)", ip, f"snmpget -v 2c -c public {ip} iso.3.6.1.2.1.1.1.0", bool)
def ntp(ip): testar_porta("NTP (123/udp)", ip, f"ntpq -c rv {ip}", lambda x: "timed out" not in x and "not running" not in x)
def ldap(ip): testar_porta("LDAP (389/udp)", ip, f"ldapsearch -x -h {ip} -s base 2> /dev/null | hexdump -C", bool)
def ubnt(ip): testar_porta("UBNT (10001/udp)", ip, f"printf '\\x01\\x00\\x00\\x00' | nc -w 3 -u {ip} 10001 | hexdump -C", bool)
def chargen(ip): testar_porta("CHARGEN (19/udp)", ip, f"echo | nc -w 1 -u {ip} 19 | hexdump -C", bool)
def qotd(ip): testar_porta("QOTD (17/udp)", ip, f"echo | nc -w 1 -u {ip} 17 | hexdump -C", bool)
def memcached(ip): testar_porta("MEMCACHED (11211/udp)", ip, f"printf '\\x0\\x0\\x0\\x0\\x0\\x1\\x0\\x0\\x73\\x74\\x61\\x74\\x73\\x0a' | nc -w 3 -u {ip} 11211 | hexdump -C", bool)
def ws_discovery(ip): testar_porta("WS-DISCOVERY (3702/udp)", ip, f"printf '<\\252>\\n' | nc -w 3 -u {ip} 3702 | hexdump -C", bool)
def coap(ip): testar_porta("CoAP (5683/udp)", ip, f"printf '\\x40\\x01\\x7d\\x70\\xbb\\x2e\\x77\\x65\\x6c\\x6c\\x2d\\x6b\\x6e\\x6f\\x77\\x6e\\x04\\x63\\x6f\\x72\\x65' | nc -w3 -u {ip} 5683| hexdump -C", bool)
def mt4145(ip): testar_porta("MT4145 (4145/tcp)", ip, f"nmap -sT -pT:4145 -Pn -n {ip} | grep open | awk '{{print $2}}'", lambda x: "open" in x)
def mt5678(ip): testar_porta("MT5678 - botnet Meris (5678/tcp)", ip, f"nmap -sT -pT:5678 -Pn -n {ip} | grep open | awk '{{print $2}}'", lambda x: "open" in x)

FUNCOES = [netbios, dhcpdiscover, rpc, arms, tftp, dns, mdns, ssdp, snmp, ntp, ldap, ubnt, chargen, qotd, memcached, ws_discovery, coap, mt4145, mt5678]

def salvar_resultados(rede):
    """Salva os resultados em um arquivo JSON."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    arquivo_nome = f"/tmp/{rede.replace('/', '_')}-{timestamp}.json"
    with open(arquivo_nome, "w") as arquivo:
        json.dump(resultados, arquivo, indent=4)
    logging.info(f"\nResultados salvos em '/tmp/{arquivo_nome}'.")

def main():
    import argparse

    global default_timeout

    parser = argparse.ArgumentParser(description="Scanner serviços usados para amplificação DDoS.")
    parser.add_argument("rede", help="IP ou rede para busca (exemplo: 192.168.0.0/24)")
    parser.add_argument("--threads", type=int, default=default_threads, help="Número de threads (padrão: 50)")
    parser.add_argument("--timeout", type=int, default=default_timeout, help="Timeout em segundos para cada comando (padrão: 5)")
    parser.add_argument("--no-progress", action="store_true", help="Desativa a barra de progresso")

    args = parser.parse_args()

    default_timeout = args.timeout

    try:
        ips = list(ipaddress.IPv4Network(args.rede, strict=False))
    except ValueError as e:
        logging.error(f"Erro ao interpretar a rede: {e}")
        sys.exit(1)

    verificar_programas()

    progress = not args.no_progress
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futuros = {executor.submit(lambda ip: [f(ip) for f in FUNCOES], str(ip)): ip for ip in ips}
        if progress:
            for futuro in tqdm(as_completed(futuros), total=len(futuros), desc="Testando IPs"):
                futuro.result()
        else:
            for futuro in as_completed(futuros):
                futuro.result()

    salvar_resultados(args.rede)

    import os
    os.system("stty sane")

if __name__ == "__main__":
    main()

