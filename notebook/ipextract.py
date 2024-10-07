import subprocess
import re

def get_public_ip():
    result = subprocess.run(['ifconfig'], stdout=subprocess.PIPE, text=True)
    inet_pattern = r'inet (\d+\.\d+\.\d+\.\d+)'
    ipv4_addresses = re.findall(inet_pattern, result.stdout)
    public_ips = [ip for ip in ipv4_addresses if ip != '127.0.0.1']
    if public_ips:
        return public_ips[0]
    else:
        return "No public IPv4 address found."

public_ip = get_public_ip()
print(f"Your public IPv4 address is: {public_ip}")
