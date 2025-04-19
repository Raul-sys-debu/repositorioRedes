import socket
import ipaddress
import platform
import os
from multiprocessing import cpu_count
from concurrent.futures import ThreadPoolExecutor, as_completed

# Validar IP (solo IPv4)
def validar_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version == 4
    except ValueError:
        return False

# Validar subred
def validar_subred(subred):
    try:
        ipaddress.ip_network(subred, strict=False)
        return True
    except ValueError:
        return False

# Escanear un solo puerto
def scan_port(host, port, timeout=0.3):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return port if result == 0 else None
    except:
        return None

# Escaneo de puertos optimizado
def port_scan(host, puertos=range(1, 65536), callback=print):
    if not validar_ip(host):
        callback(f"[!] IP inválida: {host}")
        return []

    callback(f"\n[+] Escaneando {host} - Total puertos: {len(puertos)}")
    callback("[+] Mostrando resultados en tiempo real...\n")

    abiertos = []
    max_hilos = min(500, cpu_count() * 5)

    with ThreadPoolExecutor(max_workers=max_hilos) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in puertos}

        for future in as_completed(futures):
            port = futures[future]
            try:
                result = future.result()
                if result:
                    abiertos.append(result)
                    callback(f"[+] Puerto {port} - ABIERTO")
            except Exception as e:
                callback(f"[!] Error escaneando puerto {port}: {e}")

    callback(f"\n[+] Escaneo completado: {len(abiertos)} puertos abiertos encontrados.")
    return abiertos

# Ping sweep optimizado
def ping_sweep(subred, callback=print):
    if not validar_subred(subred):
        callback(f"[!] Subred inválida: {subred}")
        return []

    callback(f"[+] Iniciando Ping Sweep sobre {subred}...\n")
    activos = []

    def ping(ip):
        param = "-n 1 -w 100" if os.name == "nt" else "-c 1 -W 1"
        response = os.system(f"ping {param} {ip} > {'nul' if os.name == 'nt' else '/dev/null'} 2>&1")
        return str(ip) if response == 0 else None

    max_hilos = min(500, cpu_count() * 5)
    with ThreadPoolExecutor(max_workers=max_hilos) as executor:
        futures = {executor.submit(ping, str(ip)): ip for ip in ipaddress.ip_network(subred, strict=False).hosts()}

        for future in as_completed(futures):
            ip = futures[future]
            try:
                result = future.result()
                if result:
                    activos.append(result)
                    callback(f"[+] Host activo: {result}")
            except Exception as e:
                callback(f"[!] Error al hacer ping a {ip}: {e}")

    callback(f"\n[+] Ping Sweep completado: {len(activos)} hosts activos.")
    return activos

# Estimar sistema operativo remoto
def fingerprint_os(host, callback=print):
    if not validar_ip(host):
        callback(f"[!] IP inválida: {host}")
        return "Desconocido"

    try:
        param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
        cmd = f"ping {param} {host}"
        with os.popen(cmd) as ping_process:
            response = ping_process.read()

        if "ttl" in response.lower():
            ttl_line = next((line for line in response.splitlines() if "ttl" in line.lower()), "")
            ttl_value = int(''.join(filter(str.isdigit, ttl_line.split('ttl')[-1])))

            if ttl_value <= 64:
                sistema = "Linux/Unix"
            elif ttl_value <= 128:
                sistema = "Windows"
            elif ttl_value <= 255:
                sistema = "Cisco/Dispositivo de red"
            else:
                sistema = "Desconocido"
            callback(f"[+] Sistema operativo estimado: {sistema} (TTL: {ttl_value})")
            return sistema
        else:
            callback("[!] No se pudo estimar el sistema operativo remoto.")
            return "No detectado"
    except Exception as e:
        callback(f"[!] Error al identificar SO remoto: {e}")
        return "Error"

# Menú interactivo
if __name__ == "__main__":
    while True:
        print("\n===== ESCÁNER DE RED - OPCIONES =====")
        print("1. Escaneo de puertos")
        print("2. Ping Sweep (descubrir hosts activos)")
        print("3. Detección del sistema operativo remoto")
        print("4. Salir")

        opcion = input("\nSelecciona una opción (1-4): ").strip()

        if opcion == "1":
            host = input("Ingresa la IP del host a escanear: ").strip()
            if not validar_ip(host):
                print("[!] IP inválida.")
                continue

            rango = input("¿Qué rango de puertos deseas escanear? (Ej: 1-1024 o presiona Enter para todos): ").strip()
            if rango:
                try:
                    start, end = map(int, rango.split('-'))
                    puertos = range(start, end + 1)
                except:
                    print("[!] Rango inválido.")
                    continue
            else:
                puertos = range(1, 65536)

            port_scan(host, puertos)

        elif opcion == "2":
            subred = input("Ingresa la subred (Ej: 192.168.1.0/24): ").strip()
            ping_sweep(subred)

        elif opcion == "3":
            host = input("Ingresa la IP del host a analizar: ").strip()
            fingerprint_os(host)

        elif opcion == "4":
            print("Saliendo... ¡Hasta luego!")
            break
        else:
            print("[!] Opción no válida.")