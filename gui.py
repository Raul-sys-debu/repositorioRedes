# Importamos las librerías necesarias
import tkinter as tk  # Librería para la creación de interfaces gráficas
from tkinter import ttk, scrolledtext  # Componentes adicionales de tkinter, como los estilos y el texto desplazable
import threading  # Librería para trabajar con hilos (threads) y ejecutar tareas de manera concurrente
import platform  # Librería para obtener información sobre el sistema operativo
import scanner  # Importamos el archivo scanner.py que contiene las funciones de escaneo

class NetworkScannerApp:
    def __init__(self, root):
        # Inicializa la aplicación con la ventana principal (root)
        self.root = root
        self.root.title("Scanner")  # Título de la ventana principal
        self.root.geometry("900x600")  # Tamaño de la ventana
        self.root.configure(bg="#2b2b2b")  # Configura el color de fondo de la ventana
        self.estilo_dark()  # Aplica el estilo de interfaz "oscura"
        self.create_widgets()  # Crea los widgets (componentes) de la interfaz gráfica

    def estilo_dark(self):
        # Configura los estilos de la interfaz con un tema oscuro
        style = ttk.Style()  # Crea un objeto Style para configurar los estilos
        style.theme_use("clam")  # Utiliza el tema "clam" que es un tema básico de tkinter
        # Configura los estilos de los diferentes widgets
        style.configure("TFrame", background="#2b2b2b")
        style.configure("TLabel", background="#2b2b2b", foreground="white")
        style.configure("TEntry", fieldbackground="#3c3f41", foreground="white", background="#2b2b2b")
        style.configure("TButton", background="#3c3f41", foreground="white")
        style.map("TButton", background=[("active", "#5c5f61")])  # Cambia el color de fondo cuando el botón está activo
        style.configure("TLabelframe", background="#2b2b2b", foreground="white")
        style.configure("TLabelframe.Label", background="#2b2b2b", foreground="white")

    def create_widgets(self):
        # Crea los widgets (componentes) de la interfaz gráfica
        main_frame = ttk.Frame(self.root, padding="10")  # Crea un marco principal con un relleno de 10 píxeles
        main_frame.pack(fill=tk.BOTH, expand=True)  # Empaqueta el marco para que se ajuste a la ventana

        # BANNER SUPERIOR
        header = tk.Label(
            main_frame,
            text="Scanner",  # Título de la aplicación
            font=("Helvetica", 16, "bold"),  # Fuente y tamaño del texto
            bg="#1e1e1e",  # Color de fondo
            fg="#00ff88",  # Color del texto
            padx=10, pady=10  # Relleno alrededor del texto
        )
        header.pack(fill=tk.X)  # Empaqueta el encabezado y lo ajusta al ancho

        # ESTRUCTURA PRINCIPAL
        content_frame = ttk.Frame(main_frame)  # Crea el marco de contenido
        content_frame.pack(fill=tk.BOTH, expand=True)  # Empaqueta el marco para que ocupe el espacio disponible

        control_frame = ttk.Labelframe(content_frame, text="Controles", padding="10")  # Crea un marco para los controles
        control_frame.pack(side=tk.LEFT, fill=tk.Y)  # Empaqueta el marco a la izquierda

        result_frame = ttk.Labelframe(content_frame, text="Resultados", padding="10")  # Crea un marco para los resultados
        result_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)  # Empaqueta el marco a la derecha y expande

        # === ENTRADAS ===
        # Crea las entradas para las direcciones IP, los puertos y las subredes
        self.entry_host = self.crear_entrada(control_frame, "Host :", "192.168.1.1")
        self.entry_puertos = self.crear_entrada(control_frame, "Puertos (ej: 0,65535):", "0,1024")
        self.entry_subred = self.crear_entrada(control_frame, "Subred (ej: 192.168.1.0/24):", "192.168.1.0/24")

        # === BOTONES ===
        # Crea los botones para ejecutar las diferentes tareas
        self.btn_so_local = ttk.Button(control_frame, text="SO Local", command=lambda: self.thread_tarea(self.ejecutar_so_local))
        self.btn_so_local.pack(fill=tk.X, pady=3)

        self.btn_so_remoto = ttk.Button(control_frame, text="SO Remoto", command=lambda: self.thread_tarea(self.ejecutar_so_remoto))
        self.btn_so_remoto.pack(fill=tk.X, pady=3)

        self.btn_puertos = ttk.Button(control_frame, text="Escanear Puertos", command=lambda: self.thread_tarea(self.ejecutar_puertos))
        self.btn_puertos.pack(fill=tk.X, pady=3)

        self.btn_ping = ttk.Button(control_frame, text="Ping Sweep", command=lambda: self.thread_tarea(self.ejecutar_ping))
        self.btn_ping.pack(fill=tk.X, pady=3)

        self.botones = [self.btn_so_local, self.btn_so_remoto, self.btn_puertos, self.btn_ping]  # Lista de botones para controlar el estado

        # === RESULTADOS ===
        # Crea un área de texto desplazable para mostrar los resultados
        self.resultado_text = scrolledtext.ScrolledText(
            result_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#1e1e1e",  # Color de fondo del área de texto
            fg="#00ff88",  # Color del texto
            insertbackground="white"  # Color del cursor de inserción
        )
        self.resultado_text.pack(fill=tk.BOTH, expand=True)  # Empaqueta el área de texto

        # Crea un botón para limpiar los resultados
        ttk.Button(result_frame, text="Limpiar", command=self.limpiar_resultados).pack(fill=tk.X, pady=5)

    def crear_entrada(self, parent, label_text, default=""):
        # Crea una etiqueta y una entrada de texto en el contenedor dado
        ttk.Label(parent, text=label_text).pack(anchor=tk.W)  # Etiqueta para la entrada
        entry = ttk.Entry(parent)  # Crea la entrada de texto
        entry.insert(0, default)  # Inserta un valor predeterminado en la entrada
        entry.pack(fill=tk.X, pady=3)  # Empaqueta la entrada
        return entry  # Devuelve la entrada creada

    def thread_tarea(self, funcion):
        # Ejecuta una tarea en un hilo independiente para evitar bloquear la interfaz gráfica
        self.deshabilitar_botones()  # Deshabilita los botones para evitar que se ejecuten varias tareas al mismo tiempo
        threading.Thread(target=self.run_tarea, args=(funcion,), daemon=True).start()  # Inicia el hilo de ejecución de la tarea

    def run_tarea(self, funcion):
        # Ejecuta la función pasada en el hilo
        try:
            funcion()  # Ejecuta la función
        except Exception as e:
            self.mostrar_resultado(f"Error: {str(e)}")  # Si ocurre un error, muestra el mensaje de error
        finally:
            self.habilitar_botones()  # Habilita los botones después de completar la tarea

    def deshabilitar_botones(self):
        # Deshabilita todos los botones de la interfaz
        for b in self.botones:
            b.config(state=tk.DISABLED)

    def habilitar_botones(self):
        # Habilita todos los botones de la interfaz
        for b in self.botones:
            b.config(state=tk.NORMAL)

    def mostrar_resultado(self, texto):
        # Muestra el texto dado en el área de resultados
        self.resultado_text.insert(tk.END, texto + "\n")  # Inserta el texto en el área de resultados
        self.resultado_text.see(tk.END)  # Desplaza el texto hacia abajo para mostrar el último mensaje
        self.resultado_text.update_idletasks()  # Actualiza la interfaz para mostrar el texto de inmediato

    def limpiar_resultados(self):
        # Limpia el área de resultados
        self.resultado_text.delete(1.0, tk.END)

    def ejecutar_so_local(self):
        # Ejecuta la tarea de identificar el sistema operativo local
        self.limpiar_resultados()
        self.mostrar_resultado("=== Identificando SO Local ===")
        so = platform.platform()  # Obtiene el sistema operativo local
        self.mostrar_resultado(f"Sistema Operativo Local: {so}")

    def ejecutar_so_remoto(self):
        # Ejecuta la tarea de identificar el sistema operativo remoto
        host = self.entry_host.get().strip()  # Obtiene la IP del host desde la entrada
        if not scanner.validar_ip(host):  # Valida si la IP es correcta
            self.mostrar_resultado("Error: Dirección IP inválida.")
            return
        self.limpiar_resultados()
        self.mostrar_resultado(f"=== Identificando SO Remoto en {host} ===")
        scanner.fingerprint_os(host, self.mostrar_resultado)  # Llama a la función del scanner para detectar el SO

    def ejecutar_puertos(self):
        # Ejecuta la tarea de escanear puertos
        host = self.entry_host.get().strip()
        puertos_str = self.entry_puertos.get().strip()

        if not scanner.validar_ip(host):
            self.mostrar_resultado("Error: Dirección IP inválida.")
            return

        # Convierte la cadena de puertos a una lista de puertos
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
        scanner.port_scan(host, puertos, self.mostrar_resultado)

    def ejecutar_ping(self):
        # Ejecuta la tarea de realizar un ping sweep en una subred
        subred = self.entry_subred.get().strip()
        if not scanner.validar_subred(subred):
            self.mostrar_resultado("Error: Subred inválida.")
            return

        self.limpiar_resultados()
        self.mostrar_resultado(f"=== Realizando Ping Sweep en {subred} ===")
        scanner.ping_sweep(subred, self.mostrar_resultado)  # Llama a la función del scanner para realizar el ping sweep

# Inicia la aplicación cuando se ejecuta este script
if __name__ == "__main__":
    root = tk.Tk()  # Crea la ventana principal
    app = NetworkScannerApp(root)  # Crea la instancia de la aplicación
    root.mainloop()  # Ejecuta el bucle principal de tkinter
