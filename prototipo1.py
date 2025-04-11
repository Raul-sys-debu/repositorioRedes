import socket
import ipaddress
import subprocess
import platform
from datetime import datetime

# Guardar resultados en archivo
def guardar_en_txt(texto):
    with open("reporte.txt", "a", encoding="utf-8") as f:
        f.write(texto + "\n")

# Realiza ping a un host
def ping(host, timeout=1):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        result = subprocess.run(['ping', param, '1', host],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

# Escanea una red completa
def ping_sweep(network, timeout=1):
    print(f"\n[+] Escaneando red: {network}")
    guardar_en_txt(f"\n[+] Escaneando red: {network}")
    activos = []
    try:
        red = ipaddress.IPv4Network(network, strict=False)
    except ValueError:
        print("[!] Subred inválida. Intenta con formato: 192.168.1.0/24")
        return []

    for ip in red:
        ip_str = str(ip)
        if ping(ip_str, timeout):
            print(f"[+] Host activo: {ip_str}")
            guardar_en_txt(f"[+] Host activo: {ip_str}")
            activos.append(ip_str)
    return activos

# Menú solo para escaneo de red
def main():
    print("=" * 50)
    print("        ESCÁNER DE IP (Ping Sweep)         ")
    print("=" * 50)
    guardar_en_txt("=" * 50)
    guardar_en_txt(f"ESCÁNER DE IP - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    guardar_en_txt("=" * 50)

    red = input("Ingresa la subred (ej. 192.168.1.0/24): ")
    ping_sweep(red)

    print("Escaneo finalizado. Resultados guardados en 'reporte.txt'.")

if __name__ == "__main__":
    main()
