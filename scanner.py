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

# Función para validar IP
def validar_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# Validar subred con formato CIDR (ej: 192.168.1.0/24)
def validar_subred(subred):
    try:
        ipaddress.IPv4Network(subred, strict=False)
        return True
    except ValueError:
        return False

# Realiza ping a un host
def ping(host, timeout=0.5):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        result = subprocess.run(['ping', param, '1', host],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        return host if result.returncode == 0 else None
    except Exception:
        return None

# Escanea red
def ping_sweep(network, timeout=0.5):
    if not validar_subred(network):
        print("[!] Subred inválida. Intenta con formato: 192.168.1.0/24")
        return []

    print(f"\n[+] Escaneando red: {network}")
    guardar_en_txt(f"\n[+] Escaneando red: {network}")
    activos = []

    red = ipaddress.IPv4Network(network, strict=False)
    with ThreadPoolExecutor(max_workers=800) as executor:
        futures = [executor.submit(ping, str(ip), timeout) for ip in red]
        for future in futures:
            result = future.result()
            if result:
                print(f"[+] Host activo: {result}")
                guardar_en_txt(f"[+] Host activo: {result}")
                activos.append(result)

    return activos

# Escanea un puerto específico
def scan_port(host, port, timeout=0.5):
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
    except:
        return None
    return None

# Escanea múltiples puertos
def port_scan(host, ports, timeout=0.5):
    print(f"\n[+] Escaneando puertos en {host}...")
    guardar_en_txt(f"\n[+] Escaneando puertos en {host}...")
    abiertos = []

    with ThreadPoolExecutor(max_workers=800) as executor:
        futures = [executor.submit(scan_port, host, port, timeout) for port in ports]
        for future in futures:
            result = future.result()
            if result:
                print(f"[+] Puerto {result[0]} abierto - Banner: {result[1]}")
                guardar_en_txt(f"[+] Puerto {result[0]} abierto - Banner: {result[1]}")
                abiertos.append(result)
    return abiertos

# Identificar SO local
def identificar_sistema_operativo():
    print("\n[+] Identificando el sistema operativo del host local...")
    os_info = platform.platform()
    print(f"[+] Sistema operativo del host local: {os_info}")
    guardar_en_txt(f"[+] Sistema operativo del host local: {os_info}")

# Identificar SO remoto por TTL
def fingerprint_os(host):
    print(f"\n[+] Intentando identificar el sistema operativo del host remoto ({host})...")
    guardar_en_txt(f"\n[+] Identificando el sistema operativo del host remoto ({host})...")
    try:
        ans, _ = sr(IP(dst=host)/TCP(dport=80, flags="S"), timeout=1, verbose=False)
        if ans:
            for _, rcv in ans:
                ttl = rcv.ttl
                os = ttl_to_os(ttl)
                print(f"[+] Sistema operativo identificado: Probablemente TTL={ttl} corresponde a {os}")
                guardar_en_txt(f"[+] Sistema operativo identificado: Probablemente TTL={ttl} corresponde a {os}")
        else:
            print("[!] No se obtuvo respuesta del host.")
            guardar_en_txt("[!] No se obtuvo respuesta del host.")
    except Exception:
        print("[!] Error al identificar el sistema operativo.")
        guardar_en_txt("[!] Error al identificar el sistema operativo.")

# Mapeo de TTL a SO
def ttl_to_os(ttl):
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Desconocido"

# Menú principal
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
            red = input("Ingresa la subred (ej. 192.168.1.0/24): ")
            if not validar_subred(red):
                print("[!] Subred inválida. Usa el formato 192.168.1.0/24")
                continue
            ping_sweep(red)

        elif opcion == "2":
            host = input("Ingresa la IP del host objetivo: ")
            if not validar_ip(host):
                print("[!] Dirección IP inválida. Debe ser una dirección IPv4.")
                continue
            try:
                rango = input("Ingresa el rango de puertos (ej. 0-65535): ")
                inicio, fin = map(int, rango.split('-'))
                if 0 <= inicio <= 65535 and 0 <= fin <= 65535 and inicio <= fin:
                    ports = range(inicio, fin + 1)
                    port_scan(host, ports)
                else:
                    print("[!] El rango de puertos es inválido.")
            except Exception:
                print("[!] Error en el formato del rango de puertos.")

        elif opcion == "3":
            host = input("Ingresa la IP del host objetivo: ")
            if not validar_ip(host):
                print("[!] Dirección IP inválida. Debe ser una dirección IPv4.")
                continue
            fingerprint_os(host)

        elif opcion == "4":
            print("Saliendo... El reporte ha sido guardado en 'reporte.txt'")
            guardar_en_txt("=" * 50)
            guardar_en_txt("FIN DEL ESCANEO")
            guardar_en_txt("=" * 50)
            break

        else:
            print("Opción inválida. Intenta de nuevo.")

# Ejecutar si se usa directamente
#if __name__ == "__main__":
#    main()
