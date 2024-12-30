import subprocess
import re

# Adicione os prefixos que deseja realizar os testes.
ip_blocks = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

output_file = "/tmp/static_loop.txt"

open(output_file, "w").close()

def get_inetnum_addresses(ip_block):
    """Obtém os endereços inetnum do bloco IP usando o comando whois."""
    try:
        result = subprocess.run(
            ["whois", "-h", "whois.lacnic.net", ip_block],
            text=True,
            capture_output=True,
            check=True,
        )
        inetnum_lines = re.findall(r"inetnum:\s+(\S+)", result.stdout)
        return [line for line in inetnum_lines if ":" not in line]
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar whois para {ip_block}: {e}")
        return []

def ping_address(address):
    """Executa o comando fping para um endereço e retorna os resultados."""
    try:
        result = subprocess.run(
            ["fping", "-gae", address],
            text=True,
            capture_output=True,
        )
        return result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        return e.output.decode("utf-8") if e.output else ""

for block in ip_blocks:
    addresses = get_inetnum_addresses(block)
    for address in addresses:
        output = ping_address(address)
        with open("/tmp/lista", "w") as temp_file:
            temp_file.write(output)
        
        with open("/tmp/lista", "r") as temp_file:
            results = temp_file.readlines()
        
        filtered_results = [
            line for line in results if "Time Exceeded" in line and "<-" not in line
        ]
        unique_results = sorted(set(filtered_results))
        
        with open(output_file, "a") as out_file:
            out_file.writelines(unique_results)
        
        subprocess.run(["rm", "-f", "/tmp/lista"])

print(f"Processo concluído. Resultados salvos em {output_file}")
