import socket
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import platform
from scapy.all import sr, IP, TCP

# Guardar resultados en archivo
def guardar_en_txt(texto):
    with open("reporte.txt", "a", encoding="utf-8") as f:
        f.write(texto + "\n")

# Realiza ping a un host
def ping(host, timeout=1):
    try:
        result = subprocess.run(['ping', '-n', '1', '-w', str(timeout * 1000), host],
                                stdout=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

# Escanea una red completa (ping sweep)
def ping_sweep(network, timeout=1):
    print(f"\n[+] Escaneando red: {network}")
    guardar_en_txt(f"\n[+] Escaneando red: {network}")
    activos = []
    for ip in ipaddress.IPv4Network(network, strict=False):
        ip_str = str(ip)
        if ping(ip_str, timeout):
            print(f"[+] Host activo: {ip_str}")
            guardar_en_txt(f"[+] Host activo: {ip_str}")
            activos.append(ip_str)
    return activos

# Escanea un puerto específico
def scan_port(host, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                try:
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except:
                    banner = "Sin banner"
                return (port, banner)
    except Exception:
        return None
    return None

# Escanea múltiples puertos
def port_scan(host, ports, timeout=1):
    print(f"\n[+] Escaneando puertos en {host}...")
    guardar_en_txt(f"\n[+] Escaneando puertos en {host}...")
    abiertos = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, host, port, timeout) for port in ports]
        for future in futures:
            result = future.result()
            if result:
                print(f"[+] Puerto {result[0]} abierto - Banner: {result[1]}")
                guardar_en_txt(f"[+] Puerto {result[0]} abierto - Banner: {result[1]}")
                abiertos.append(result)
    return abiertos

# Identificar el sistema operativo local
def identificar_sistema_operativo():
    print("\n[+] Identificando el sistema operativo del host local...")
    os_info = platform.platform()
    print(f"[+] Sistema operativo del host local: {os_info}")
    guardar_en_txt(f"[+] Sistema operativo del host local: {os_info}")

# Fingerprinting para identificar sistema remoto (Scapy)
def fingerprint_os(host):
    print(f"\n[+] Intentando identificar el sistema operativo del host remoto ({host})...")
    guardar_en_txt(f"\n[+] Identificando el sistema operativo del host remoto ({host})...")
    try:
        ans, _ = sr(IP(dst=host)/TCP(dport=80, flags="S"), timeout=1, verbose=False)
        if ans:
            for _, rcv in ans:
                ttl = rcv.ttl
                print(f"[+] Sistema operativo identificado: Probablemente TTL={ttl} corresponde a {ttl_to_os(ttl)}")
                guardar_en_txt(f"[+] Sistema operativo identificado: Probablemente TTL={ttl} corresponde a {ttl_to_os(ttl)}")
    except Exception as e:
        print("[!] No se pudo identificar el sistema operativo.")

# TTL-to-OS mapping (aproximación simple)
def ttl_to_os(ttl):
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Desconocido"

# Menú principal interactivo
def main():
    print("=" * 50)
    print("          ESCÁNER AVANZADO DE RED LOCAL         ")
    print("=" * 50)
    guardar_en_txt("=" * 50)
    guardar_en_txt(f"INICIO DEL ESCANEO - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    guardar_en_txt("=" * 50)

    identificar_sistema_operativo()

    while True:
        print("\n¿Qué deseas hacer?")
        print("1) Escanear red para encontrar hosts activos")
        print("2) Escanear puertos en un host específico")
        print("3) Identificar el sistema operativo de un host remoto")
        print("4) Salir")
        opcion = input("Elige una opción (1, 2, 3 o 4): ")

        if opcion == "1":
            red = input("Ingresa la subred : ")
            ping_sweep(red)

        elif opcion == "2":
            host = input("Ingresa la IP del host objetivo: ")
            rango = input("Ingresa el rango de puertos (ej. 20-100): ")
            try:
                inicio, fin = map(int, rango.split('-'))
                ports = range(inicio, fin + 1)
                port_scan(host, ports)
            except:
                print("[!] Error en el formato del rango de puertos.")

        elif opcion == "3":
            host = input("Ingresa la IP del host objetivo: ")
            fingerprint_os(host)

        elif opcion == "4":
            print("Saliendo... El reporte ha sido guardado en 'reporte.txt'")
            guardar_en_txt("=" * 50)
            guardar_en_txt("FIN DEL ESCANEO")
            guardar_en_txt("=" * 50)
            break

        else:
            print("Opción inválida. Intenta de nuevo.")

if __name__ == "__main__":
    main()