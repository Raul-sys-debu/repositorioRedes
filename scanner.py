import socket  # Importa el módulo socket para manejar conexiones de red.
import ipaddress  # Importa el módulo ipaddress para trabajar con direcciones IP.
import platform  # Importa el módulo platform para obtener información sobre el sistema operativo.
import os  # Importa el módulo os para interactuar con el sistema operativo.
from multiprocessing import cpu_count  # Importa la función cpu_count para obtener el número de núcleos del procesador.
from concurrent.futures import ThreadPoolExecutor, as_completed  # Importa las herramientas para manejar concurrencia con hilos.

# Validar IP (solo IPv4)
def validar_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)  # Intenta convertir la IP en un objeto ip_address.
        return ip_obj.version == 4  # Verifica si la IP es IPv4.
    except ValueError:
        return False  # Si ocurre un error, devuelve False, indicando que la IP no es válida.

# Validar subred
def validar_subred(subred):
    try:
        ipaddress.ip_network(subred, strict=False)  # Intenta interpretar la subred como una red válida.
        return True  # Si es válida, devuelve True.
    except ValueError:
        return False  # Si ocurre un error, devuelve False, indicando que la subred no es válida.

# Escanear un solo puerto
def scan_port(host, port, timeout=0.3):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # Crea un socket TCP IPv4.
            s.settimeout(timeout)  # Establece un tiempo de espera para la conexión.
            result = s.connect_ex((host, port))  # Intenta conectar al puerto.
            return port if result == 0 else None  # Si la conexión es exitosa, devuelve el puerto; de lo contrario, None.
    except:
        return None  # Si ocurre un error, devuelve None.

# Escaneo de puertos optimizado
def port_scan(host, puertos=range(1, 65536), callback=print):
    if not validar_ip(host):  # Verifica si la IP del host es válida.
        callback(f"[!] IP inválida: {host}")  # Si no es válida, muestra un mensaje.
        return []  # Devuelve una lista vacía si la IP es inválida.

    callback(f"\n[+] Escaneando {host} - Total puertos: {len(puertos)}")  # Muestra información sobre el inicio del escaneo.
    callback("[+] Mostrando resultados en tiempo real...\n")  # Indica que los resultados se mostrarán en tiempo real.

    abiertos = []  # Lista para almacenar los puertos abiertos.
    max_hilos = min(500, cpu_count() * 5)  # Define el número máximo de hilos (hilos disponibles por CPU, hasta un máximo de 500).

    with ThreadPoolExecutor(max_workers=max_hilos) as executor:  # Crea un ejecutor de hilos con el número máximo de hilos.
        futures = {executor.submit(scan_port, host, port): port for port in puertos}  # Envia las tareas de escaneo de puertos a los hilos.

        for future in as_completed(futures):  # Itera cuando un hilo termine su tarea.
            port = futures[future]  # Obtiene el puerto asociado con el hilo.
            try:
                result = future.result()  # Obtiene el resultado del escaneo del puerto.
                if result:  # Si el puerto está abierto, lo agrega a la lista de puertos abiertos.
                    abiertos.append(result)
                    callback(f"[+] Puerto {port} - ABIERTO")  # Muestra el puerto abierto.
            except Exception as e:
                callback(f"[!] Error escaneando puerto {port}: {e}")  # Muestra un error si ocurre.

    callback(f"\n[+] Escaneo completado: {len(abiertos)} puertos abiertos encontrados.")  # Muestra el resumen del escaneo.
    return abiertos  # Devuelve la lista de puertos abiertos.

# Ping sweep optimizado
def ping_sweep(subred, callback=print):
    if not validar_subred(subred):  # Verifica si la subred es válida.
        callback(f"[!] Subred inválida: {subred}")  # Muestra un mensaje si la subred no es válida.
        return []  # Devuelve una lista vacía si la subred es inválida.

    callback(f"[+] Iniciando Ping Sweep sobre {subred}...\n")  # Muestra un mensaje indicando que se inicia el Ping Sweep.
    activos = []  # Lista para almacenar las IPs activas.

    def ping(ip):  # Función interna para hacer ping a una dirección IP.
        param = "-n 1 -w 100" if os.name == "nt" else "-c 1 -W 1"  # Ajusta los parámetros según el sistema operativo.
        response = os.system(f"ping {param} {ip} > {'nul' if os.name == 'nt' else '/dev/null'} 2>&1")  # Ejecuta el comando ping.
        return str(ip) if response == 0 else None  # Si la respuesta es exitosa (host activo), devuelve la IP.

    max_hilos = min(500, cpu_count() * 5)  # Define el número máximo de hilos para el Ping Sweep.
    with ThreadPoolExecutor(max_workers=max_hilos) as executor:  # Crea un ejecutor de hilos.
        futures = {executor.submit(ping, str(ip)): ip for ip in ipaddress.ip_network(subred, strict=False).hosts()}  # Envia las tareas de ping para cada host en la subred.

        for future in as_completed(futures):  # Itera cuando un hilo termine su tarea.
            ip = futures[future]  # Obtiene la IP asociada con el hilo.
            try:
                result = future.result()  # Obtiene el resultado del ping.
                if result:  # Si el host responde, lo agrega a la lista de activos.
                    activos.append(result)
                    callback(f"[+] Host activo: {result}")  # Muestra el host activo.
            except Exception as e:
                callback(f"[!] Error al hacer ping a {ip}: {e}")  # Muestra un error si ocurre.

    callback(f"\n[+] Ping Sweep completado: {len(activos)} hosts activos.")  # Muestra el resumen del Ping Sweep.
    return activos  # Devuelve la lista de hosts activos.

# Estimar sistema operativo remoto
def fingerprint_os(host, callback=print):
    if not validar_ip(host):  # Verifica si la IP del host es válida.
        callback(f"[!] IP inválida: {host}")  # Muestra un mensaje si la IP no es válida.
        return "Desconocido"  # Devuelve "Desconocido" si la IP es inválida.

    try:
        param = "-n 1" if platform.system().lower() == "windows" else "-c 1"  # Ajusta los parámetros de ping según el sistema operativo.
        cmd = f"ping {param} {host}"  # Crea el comando para hacer ping.
        with os.popen(cmd) as ping_process:  # Ejecuta el comando de ping y obtiene la salida.
            response = ping_process.read()

        if "ttl" in response.lower():  # Si la respuesta contiene TTL, intenta estimar el sistema operativo.
            ttl_line = next((line for line in response.splitlines() if "ttl" in line.lower()), "")  # Extrae la línea con el TTL.
            ttl_value = int(''.join(filter(str.isdigit, ttl_line.split('ttl')[-1])))  # Extrae el valor de TTL.

            # Estima el sistema operativo basado en el valor de TTL.
            if ttl_value <= 64:
                sistema = "Linux/Unix"
            elif ttl_value <= 128:
                sistema = "Windows"
            elif ttl_value <= 255:
                sistema = "Cisco/Dispositivo de red"
            else:
                sistema = "Desconocido"
            callback(f"[+] Sistema operativo estimado: {sistema} (TTL: {ttl_value})")  # Muestra el sistema operativo estimado.
            return sistema
        else:
            callback("[!] No se pudo estimar el sistema operativo remoto.")  # Si no se puede estimar el SO, muestra un mensaje.
            return "No detectado"  # Devuelve "No detectado" si no se puede estimar el SO.
    except Exception as e:
        callback(f"[!] Error al identificar SO remoto: {e}")  # Muestra un error si ocurre.
        return "Error"  # Devuelve "Error" si ocurre un fallo.

