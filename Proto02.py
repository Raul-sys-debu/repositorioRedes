
# Importamos todas las librerías necesarias
import tkinter as tk  # Librería para la creación de interfaces gráficas
from tkinter import ttk, scrolledtext  # Componentes adicionales de tkinter
import threading  # Para ejecutar tareas en segundo plano
import platform  # Para obtener información del sistema operativo
import socket  # Para operaciones de red
import ipaddress  # Para manejo de direcciones IP
import os  # Para ejecutar comandos del sistema
from multiprocessing import cpu_count  # Para obtener el número de núcleos del CPU
from concurrent.futures import ThreadPoolExecutor, as_completed  # Para manejar concurrencia

class NetworkScannerApp:
    def __init__(self, root):
        # Inicializa la aplicación con la ventana principal
        self.root = root
        self.root.title("Scanner")  # Título de la ventana
        self.root.geometry("900x600")  # Tamaño inicial de la ventana
        self.root.configure(bg="#2b2b2b")  # Color de fondo oscuro
        self.estilo_dark()  # Aplica el tema oscuro
        self.create_widgets()  # Crea los componentes de la interfaz

    def estilo_dark(self):
        # Configura el estilo visual oscuro para la interfaz
        style = ttk.Style()
        style.theme_use("clam")  # Usa el tema básico 'clam'
        
        # Configura los colores para diferentes componentes
        style.configure("TFrame", background="#2b2b2b")
        style.configure("TLabel", background="#2b2b2b", foreground="white")
        style.configure("TEntry", fieldbackground="#3c3f41", foreground="white", background="#2b2b2b")
        style.configure("TButton", background="#3c3f41", foreground="white")
        style.map("TButton", background=[("active", "#5c5f61")])  # Efecto al pasar el mouse
        style.configure("TLabelframe", background="#2b2b2b", foreground="white")
        style.configure("TLabelframe.Label", background="#2b2b2b", foreground="white")

    def create_widgets(self):
        # Crea todos los elementos visuales de la interfaz
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Encabezado de la aplicación
        header = tk.Label(
            main_frame,
            text="Scanner",
            font=("Helvetica", 16, "bold"),
            bg="#1e1e1e",
            fg="#00ff88",
            padx=10, pady=10
        )
        header.pack(fill=tk.X)

        # Estructura principal con controles y resultados
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Panel de controles (izquierda)
        control_frame = ttk.Labelframe(content_frame, text="Controles", padding="10")
        control_frame.pack(side=tk.LEFT, fill=tk.Y)

        # Panel de resultados (derecha)
        result_frame = ttk.Labelframe(content_frame, text="Resultados", padding="10")
        result_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Campos de entrada para host, puertos y subred
        self.entry_host = self.crear_entrada(control_frame, "Host :", "192.168.1.1")
        self.entry_puertos = self.crear_entrada(control_frame, "Puertos (ej: 0,65535):", "0,1024")
        self.entry_subred = self.crear_entrada(control_frame, "Subred (ej: 192.168.1.0/24):", "192.168.1.0/24")

        # Botones para las diferentes funcionalidades
        self.btn_so_local = ttk.Button(control_frame, text="SO Local", command=lambda: self.thread_tarea(self.ejecutar_so_local))
        self.btn_so_local.pack(fill=tk.X, pady=3)

        self.btn_so_remoto = ttk.Button(control_frame, text="SO Remoto", command=lambda: self.thread_tarea(self.ejecutar_so_remoto))
        self.btn_so_remoto.pack(fill=tk.X, pady=3)

        self.btn_puertos = ttk.Button(control_frame, text="Escanear Puertos", command=lambda: self.thread_tarea(self.ejecutar_puertos))
        self.btn_puertos.pack(fill=tk.X, pady=3)

        self.btn_ping = ttk.Button(control_frame, text="Ping Sweep", command=lambda: self.thread_tarea(self.ejecutar_ping))
        self.btn_ping.pack(fill=tk.X, pady=3)

        # Lista de botones para controlar su estado
        self.botones = [self.btn_so_local, self.btn_so_remoto, self.btn_puertos, self.btn_ping]

        # Área de texto para mostrar resultados
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

    def crear_entrada(self, parent, label_text, default=""):
        # Crea un campo de entrada con etiqueta
        ttk.Label(parent, text=label_text).pack(anchor=tk.W)
        entry = ttk.Entry(parent)
        entry.insert(0, default)
        entry.pack(fill=tk.X, pady=3)
        return entry

    def thread_tarea(self, funcion):
        # Ejecuta una función en un hilo separado
        self.deshabilitar_botones()
        threading.Thread(target=self.run_tarea, args=(funcion,), daemon=True).start()

    def run_tarea(self, funcion):
        # Función que ejecuta la tarea y maneja errores
        try:
            funcion()
        except Exception as e:
            self.mostrar_resultado(f"Error: {str(e)}")
        finally:
            self.habilitar_botones()

    def deshabilitar_botones(self):
        # Desactiva todos los botones durante una operación
        for b in self.botones:
            b.config(state=tk.DISABLED)

    def habilitar_botones(self):
        # Reactiva todos los botones después de una operación
        for b in self.botones:
            b.config(state=tk.NORMAL)

    def mostrar_resultado(self, texto):
        # Muestra texto en el área de resultados
        self.resultado_text.insert(tk.END, texto + "\n")
        self.resultado_text.see(tk.END)
        self.resultado_text.update_idletasks()

    def limpiar_resultados(self):
        # Limpia el área de resultados
        self.resultado_text.delete(1.0, tk.END)

    def ejecutar_so_local(self):
        # Muestra información del sistema operativo local
        self.limpiar_resultados()
        self.mostrar_resultado("=== Identificando SO Local ===")
        so = platform.platform()
        self.mostrar_resultado(f"Sistema Operativo Local: {so}")

    def ejecutar_so_remoto(self):
        # Intenta identificar el sistema operativo remoto
        host = self.entry_host.get().strip()
        if not self.validar_ip(host):
            self.mostrar_resultado("Error: Dirección IP inválida.")
            return
        
        self.limpiar_resultados()
        self.mostrar_resultado(f"=== Identificando SO Remoto en {host} ===")
        self.fingerprint_os(host)

    def ejecutar_puertos(self):
        # Realiza un escaneo de puertos en un host
        host = self.entry_host.get().strip()
        puertos_str = self.entry_puertos.get().strip()

        if not self.validar_ip(host):
            self.mostrar_resultado("Error: Dirección IP inválida.")
            return

        # Procesa el rango de puertos especificado
        try:
            if "-" in puertos_str:
                start, end = map(int, puertos_str.split("-"))
                puertos = range(start, end + 1)
            elif "," in puertos_str:
                partes = puertos_str.split(",")
                if len(partes) == 2:
                    start, end = map(int, partes)
                    puertos = range(start, end + 1)
                else:
                    puertos = [int(p) for p in partes if p.strip().isdigit()]
            else:
                puerto = int(puertos_str)
                puertos = [puerto]
        except ValueError:
            self.mostrar_resultado("Error: Formato de puertos inválido.")
            return

        self.limpiar_resultados()
        self.mostrar_resultado(f"=== Escaneando puertos en {host} ===")
        self.port_scan(host, puertos)

    def ejecutar_ping(self):
        # Realiza un ping sweep en una subred
        subred = self.entry_subred.get().strip()
        if not self.validar_subred(subred):
            self.mostrar_resultado("Error: Subred inválida.")
            return

        self.limpiar_resultados()
        self.mostrar_resultado(f"=== Realizando Ping Sweep en {subred} ===")
        self.ping_sweep(subred)

    # ==============================================
    # Funciones de escaneo (originalmente en scanner.py)
    # ==============================================

    def validar_ip(self, ip):
        # Valida una dirección IPv4
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.version == 4
        except ValueError:
            return False

    def validar_subred(self, subred):
        # Valida una notación de subred
        try:
            ipaddress.ip_network(subred, strict=False)
            return True
        except ValueError:
            return False

    def scan_port(self, host, port, timeout=0.3):
        # Escanea un puerto individual
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((host, port))
                return port if result == 0 else None
        except:
            return None

    def port_scan(self, host, puertos, callback=None):
        # Escanea múltiples puertos en un host
        if not self.validar_ip(host):
            self.mostrar_resultado(f"[!] IP inválida: {host}")
            return []

        callback = callback or self.mostrar_resultado
        callback(f"\n[+] Escaneando {host} - Total puertos: {len(puertos)}")
        callback("[+] Mostrando resultados en tiempo real...\n")

        abiertos = []
        max_hilos = min(500, cpu_count() * 5)

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

    def ping_sweep(self, subred, callback=None):
        # Descubre hosts activos en una subred
        if not self.validar_subred(subred):
            self.mostrar_resultado(f"[!] Subred inválida: {subred}")
            return []

        callback = callback or self.mostrar_resultado
        callback(f"[+] Iniciando Ping Sweep sobre {subred}...\n")
        activos = []

        def ping(ip):
            # Función interna para hacer ping a una IP
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

    def fingerprint_os(self, host, callback=None):
        # Intenta identificar el sistema operativo remoto
        if not self.validar_ip(host):
            self.mostrar_resultado(f"[!] IP inválida: {host}")
            return "Desconocido"

        callback = callback or self.mostrar_resultado
        
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

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop() 