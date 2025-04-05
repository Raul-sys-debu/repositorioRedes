import socket
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

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
    except:
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

# Menú principal interactivo
def main():
    print("=" * 50)
    print("          ESCÁNER DE RED LOCAL (PYTHON)         ")
    print("=" * 50)
    guardar_en_txt("=" * 50)
    guardar_en_txt(f"INICIO DEL ESCANEO - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    guardar_en_txt("=" * 50)

    while True:
        print("\n¿Qué deseas hacer?")
        print("1) Escanear red para encontrar hosts activos")
        print("2) Escanear puertos en un host específico")
        print("3) Salir")
        opcion = input("Elige una opción (1, 2 o 3): ")

        if opcion == "1":
            red = input("Ingresa la subred (ej. 192.168.1.0/24): ")
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
            print("Saliendo... El reporte ha sido guardado en 'reporte.txt'")
            guardar_en_txt("=" * 50)
            guardar_en_txt("FIN DEL ESCANEO")
            guardar_en_txt("=" * 50)
            break

        else:
            print("Opción inválida. Intenta de nuevo.")

if __name__ == "__main__":
    main()
