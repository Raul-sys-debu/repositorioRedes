import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Guardar resultados en archivo
def guardar_en_txt(texto):
    with open("reporte.txt", "a", encoding="utf-8") as f:
        f.write(texto + "\n")

# Escanea un solo puerto
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

# Escanea un rango de puertos
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

# Menú solo para escaneo de puertos
def main():
    print("=" * 50)
    print("        ESCÁNER DE PUERTOS         ")
    print("=" * 50)
    guardar_en_txt("=" * 50)
    guardar_en_txt(f"ESCÁNER DE PUERTOS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    guardar_en_txt("=" * 50)

    host = input("Ingresa la IP del host objetivo: ")
    try:
        socket.inet_aton(host)
        rango = input("Ingresa el rango de puertos (ej. 20-100): ")
        inicio, fin = map(int, rango.split('-'))
        if 0 <= inicio <= 65535 and 0 <= fin <= 65535 and inicio <= fin:
            ports = range(inicio, fin + 1)
            port_scan(host, ports)
        else:
            print("[!] El rango de puertos es inválido.")
    except Exception:
        print("[!] Error en el formato de IP o del rango de puertos.")

    print("Escaneo finalizado. Resultados guardados en 'reporte.txt'.")

if __name__ == "__main__":
    main()
