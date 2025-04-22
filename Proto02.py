# ================================
# IMPORTACIÓN DE LIBRERÍAS
# ================================

import tkinter as tk  # Interfaz gráfica
from tkinter import ttk, scrolledtext  # ttk = widgets modernos, scrolledtext = textbox con scroll
import threading  # Para ejecutar procesos sin bloquear la interfaz
import platform  # Información del sistema operativo
import socket  # Comunicación de red (sockets TCP/IP)
import ipaddress  # Validación y manejo de IPs y subredes
import os  # Acceso a comandos del sistema operativo
import subprocess  # Ejecutar comandos del sistema como ping
from multiprocessing import cpu_count  # Número de núcleos de CPU disponibles
from concurrent.futures import ThreadPoolExecutor, as_completed  # Manejo de concurrencia (hilos múltiples)

# ================================
# CLASE PRINCIPAL DE LA APP
# ================================

class NetworkScannerApp:
    def __init__(self, root):  # Constructor, se ejecuta al crear la app
        self.root = root  # Guarda la ventana principal
        self.root.title("Scanner")  # Título de la ventana
        self.root.geometry("900x600")  # Dimensiones de la ventana
        self.root.configure(bg="#2b2b2b")  # Fondo oscuro
        self.estilo_dark()  # Aplica tema oscuro personalizado
        self.create_widgets()  # Crea todos los componentes visuales (widgets)

    def estilo_dark(self):
        # Estilo personalizado con colores oscuros
        style = ttk.Style()
        style.theme_use("clam")  # Tema base
        style.configure("TFrame", background="#2b2b2b")  # Color de fondo para frames
        style.configure("TLabel", background="#2b2b2b", foreground="white")  # Labels blancos
        style.configure("TEntry", fieldbackground="#3c3f41", foreground="white", background="#2b2b2b")  # Campos de texto oscuros
        style.configure("TButton", background="#3c3f41", foreground="white")  # Botones oscuros
        style.map("TButton", background=[("active", "#5c5f61")])  # Color al hacer click
        style.configure("TLabelframe", background="#2b2b2b", foreground="white")  # Bordes de grupos
        style.configure("TLabelframe.Label", background="#2b2b2b", foreground="white")  # Títulos de grupos

    def create_widgets(self):
        # Frame principal con padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Título en la parte superior
        header = tk.Label(
            main_frame,
            text="Scanner",
            font=("Helvetica", 16, "bold"),
            bg="#1e1e1e",
            fg="#00ff88",
            padx=10, pady=10
        )
        header.pack(fill=tk.X)

        # Frame que contendrá controles y resultados
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Sección izquierda: controles
        control_frame = ttk.Labelframe(content_frame, text="Controles", padding="10")
        control_frame.pack(side=tk.LEFT, fill=tk.Y)

        # Sección derecha: resultados
        result_frame = ttk.Labelframe(content_frame, text="Resultados", padding="10")
        result_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Entradas de texto para IP, puertos y subred
        self.entry_host = self.crear_entrada(control_frame, "Host :", "192.168.1.1")
        self.entry_puertos = self.crear_entrada(control_frame, "Puertos (ej: 0,65535):", "0,1024")
        self.entry_subred = self.crear_entrada(control_frame, "Subred (ej: 192.168.1.0/24):", "192.168.1.0/24")

        # Botones para cada funcionalidad
        self.btn_so_local = ttk.Button(control_frame, text="SO Local", command=lambda: self.thread_tarea(self.ejecutar_so_local))
        self.btn_so_local.pack(fill=tk.X, pady=3)

        self.btn_so_remoto = ttk.Button(control_frame, text="SO Remoto", command=lambda: self.thread_tarea(self.ejecutar_so_remoto))
        self.btn_so_remoto.pack(fill=tk.X, pady=3)

        self.btn_puertos = ttk.Button(control_frame, text="Escanear Puertos", command=lambda: self.thread_tarea(self.ejecutar_puertos))
        self.btn_puertos.pack(fill=tk.X, pady=3)

        self.btn_ping = ttk.Button(control_frame, text="Ping Sweep", command=lambda: self.thread_tarea(self.ejecutar_ping))
        self.btn_ping.pack(fill=tk.X, pady=3)

        # Guardamos los botones para habilitarlos/deshabilitarlos
        self.botones = [self.btn_so_local, self.btn_so_remoto, self.btn_puertos, self.btn_ping]

        # Caja de texto para mostrar los resultados
        self.resultado_text = scrolledtext.ScrolledText(
            result_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#1e1e1e",
            fg="#00ff88",
            insertbackground="white"
        )
        self.resultado_text.pack(fill=tk.BOTH, expand=True)

        # Botón para limpiar resultados
        ttk.Button(result_frame, text="Limpiar", command=self.limpiar_resultados).pack(fill=tk.X, pady=5)

    # Función que crea un campo de entrada con etiqueta
    def crear_entrada(self, parent, label_text, default=""):
        ttk.Label(parent, text=label_text).pack(anchor=tk.W)
        entry = ttk.Entry(parent)
        entry.insert(0, default)
        entry.pack(fill=tk.X, pady=3)
        return entry

    # Ejecuta una tarea en un hilo separado para no bloquear la UI
    def thread_tarea(self, funcion):
        self.deshabilitar_botones()
        threading.Thread(target=self.run_tarea, args=(funcion,), daemon=True).start()

    def run_tarea(self, funcion):
        try:
            funcion()
        except Exception as e:
            self.mostrar_resultado(f"Error: {str(e)}")
        finally:
            self.habilitar_botones()

    def deshabilitar_botones(self):
        for b in self.botones:
            b.config(state=tk.DISABLED)

    def habilitar_botones(self):
        for b in self.botones:
            b.config(state=tk.NORMAL)

    def mostrar_resultado(self, texto):
        self.resultado_text.insert(tk.END, texto + "\n")
        self.resultado_text.see(tk.END)
        self.resultado_text.update_idletasks()

    def limpiar_resultados(self):
        self.resultado_text.delete(1.0, tk.END)

    # Función que imprime el SO del equipo local
    def ejecutar_so_local(self):
        self.limpiar_resultados()
        self.mostrar_resultado("=== Identificando SO Local ===")
        so = platform.platform()
        self.mostrar_resultado(f"Sistema Operativo Local: {so}")


        # Función para detectar el sistema operativo de un host remoto
    def ejecutar_so_remoto(self):
        host = self.entry_host.get().strip()  # Se obtiene la IP escrita por el usuario
        if not self.validar_ip(host):  # Validación de IP
            self.mostrar_resultado("Error: Dirección IP inválida.")
            return

        self.limpiar_resultados()  # Limpia la caja de resultados
        self.mostrar_resultado(f"=== Identificando SO Remoto en {host} ===")
        self.fingerprint_os(host)  # Llama a función que intenta determinar el SO remoto por el TTL

    # Función que escanea los puertos de un host
    def ejecutar_puertos(self):
        host = self.entry_host.get().strip()
        puertos_str = self.entry_puertos.get().strip()

        if not self.validar_ip(host):
            self.mostrar_resultado("Error: Dirección IP inválida.")
            return

        try:
            # Soporta diferentes formatos: rango con "-" o lista con ","
            if "-" in puertos_str:
                start, end = map(int, puertos_str.split("-"))
                if not (0 <= start <= 65535 and 0 <= end <= 65535):
                    raise ValueError
                puertos = range(start, end + 1)
            elif "," in puertos_str:
                partes = puertos_str.split(",")
                if len(partes) == 2:
                    start, end = map(int, partes)
                    if not (0 <= start <= 65535 and 0 <= end <= 65535):
                        raise ValueError
                    puertos = range(start, end + 1)
                else:
                    puertos = []
                    for p in partes:
                        num = int(p.strip())
                        if not (0 <= num <= 65535):
                            raise ValueError
                        puertos.append(num)
            else:
                puerto = int(puertos_str)
                if not (0 <= puerto <= 65535):
                    raise ValueError
                puertos = [puerto]
        except ValueError:
            self.mostrar_resultado("Error: Formato de puertos inválido o fuera de rango (0-65535).")
            return

        self.limpiar_resultados()
        self.mostrar_resultado(f"=== Escaneando puertos en {host} ===")
        self.port_scan(host, puertos)  # Llama a función que hace el escaneo

    # Ejecuta un barrido de ping sobre una subred
    def ejecutar_ping(self):
        subred = self.entry_subred.get().strip()
        if not self.validar_subred(subred):
            self.mostrar_resultado("Error: Subred inválida.")
            return

        self.limpiar_resultados()
        self.mostrar_resultado(f"=== Realizando Ping Sweep en {subred} ===")
        self.ping_sweep(subred)

    # Valida si la IP es correcta
    def validar_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.version == 4
        except ValueError:
            return False

    # Valida si una subred es válida
    def validar_subred(self, subred):
        try:
            ipaddress.ip_network(subred, strict=False)
            return True
        except ValueError:
            return False

    # Intenta conectar a un puerto del host. Devuelve el puerto si está abierto.
    def scan_port(self, host, port, timeout=0.3):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((host, port))  # 0 = éxito
                return port if result == 0 else None
        except:
            return None

    # Escaneo paralelo de puertos usando hilos
    def port_scan(self, host, puertos, callback=None):
        if not self.validar_ip(host):
            self.mostrar_resultado(f"[!] IP inválida: {host}")
            return []

        callback = callback or self.mostrar_resultado
        callback(f"\n[+] Escaneando {host} - Total puertos: {len(puertos)}")
        callback("[+] Mostrando resultados en tiempo real...\n")

        abiertos = []  # Puertos abiertos detectados
        max_hilos = min(500, cpu_count() * 5)  # Número máximo de hilos concurrentes

        # Crea un grupo de hilos para escanear puertos en paralelo
        with ThreadPoolExecutor(max_workers=max_hilos) as executor:
            futures = {executor.submit(self.scan_port, host, port): port for port in puertos}

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

    # Realiza ping a una red completa para detectar hosts activos
    def ping_sweep(self, subred, callback=None):
        if not self.validar_subred(subred):
            self.mostrar_resultado(f"[!] Subred inválida: {subred}")
            return []

        callback = callback or self.mostrar_resultado
        callback(f"[+] Iniciando Ping Sweep sobre {subred}...\n")
        activos = []

        # Función que hace ping a una IP
        def ping(ip):
            param = ["ping", "-n", "1", "-w", "100"] if os.name == "nt" else ["ping", "-c", "1", "-W", "1"]
            param.append(str(ip))
            try:
                # Windows: suprime ventana emergente
                if os.name == "nt":
                    result = subprocess.run(param, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                            creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    result = subprocess.run(param, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return str(ip) if result.returncode == 0 else None
            except Exception:
                return None

        max_hilos = min(500, cpu_count() * 5)

        # Se crean tareas para cada IP de la subred
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

    # Detección del sistema operativo remoto a partir del valor TTL en la respuesta del ping
    def fingerprint_os(self, host, callback=None):
        if not self.validar_ip(host):  
            self.mostrar_resultado(f"[!] IP inválida: {host}")
            return "Desconocido"

        callback = callback or self.mostrar_resultado

        try:
            # Parametros de ping según SO
            param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
            cmd = f"ping {param} {host}"

            # Ejecuta el ping y captura la salida
            with os.popen(cmd) as ping_process:
                response = ping_process.read()

            if "ttl" in response.lower():
                ttl_line = next((line for line in response.splitlines() if "ttl" in line.lower()), "")
                ttl_value = int(''.join(filter(str.isdigit, ttl_line.split('ttl')[-1])))

                # Estimación del SO según TTL
                if ttl_value <= 64:
                    sistema = "Linux/Unix"
                elif ttl_value <= 128:
                    sistema = "Windows"
                elif ttl_value <= 255:
                    sistema = "Cisco/Dispositivo de red"
                else:
                    sistema = "Desconocido"

                # Ajustes específicos
                if ttl_value == 255:
                    sistema = "Cisco/Router u otro dispositivo de red"
                elif ttl_value == 128:
                    sistema = "Windows (versiones recientes)"
                if ttl_value >= 64 and ttl_value <= 128:
                    sistema = "Windows o Linux/Unix (Verificación adicional necesaria)"

                callback(f"[+] Sistema operativo estimado: {sistema} (TTL: {ttl_value})")
                return sistema
            else:
                callback("[!] No se pudo obtener información de TTL, imposible detectar el SO.")
                return "No detectado"

        except Exception as e:
            callback(f"[!] Error al identificar SO remoto: {e}")
            return "Error"

# =============================
# PUNTO DE ENTRADA DEL PROGRAMA
# =============================
if __name__ == "__main__":
    root = tk.Tk()  # Crea la ventana principal
    app = NetworkScannerApp(root)  # Crea una instancia de la app
    root.mainloop()  # Inicia el bucle de eventos de la interfaz
