import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import platform
import scanner  # Asegúrate de que esté actualizado

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner")
        self.root.geometry("900x600")
        self.root.configure(bg="#2b2b2b")
        self.estilo_dark()
        self.create_widgets()

    def estilo_dark(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#2b2b2b")
        style.configure("TLabel", background="#2b2b2b", foreground="white")
        style.configure("TEntry", fieldbackground="#3c3f41", foreground="white", background="#2b2b2b")
        style.configure("TButton", background="#3c3f41", foreground="white")
        style.map("TButton", background=[("active", "#5c5f61")])
        style.configure("TLabelframe", background="#2b2b2b", foreground="white")
        style.configure("TLabelframe.Label", background="#2b2b2b", foreground="white")

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # BANNER SUPERIOR
        header = tk.Label(
            main_frame,
            text="Scanner",
            font=("Helvetica", 16, "bold"),
            bg="#1e1e1e",
            fg="#00ff88",
            padx=10, pady=10
        )
        header.pack(fill=tk.X)

        # ESTRUCTURA PRINCIPAL
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)

        control_frame = ttk.Labelframe(content_frame, text="Controles", padding="10")
        control_frame.pack(side=tk.LEFT, fill=tk.Y)

        result_frame = ttk.Labelframe(content_frame, text="Resultados", padding="10")
        result_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # === ENTRADAS ===
        self.entry_host = self.crear_entrada(control_frame, "Host Remoto:", "192.168.1.1")
        self.entry_puertos = self.crear_entrada(control_frame, "Puertos (ej: 0,65535):", "0,65535")
        self.entry_subred = self.crear_entrada(control_frame, "Subred (ej: 192.168.1.0/24):", "192.168.1.0/24")

        # === BOTONES ===
        self.btn_so_local = ttk.Button(control_frame, text="SO Local", command=lambda: self.thread_tarea(self.ejecutar_so_local))
        self.btn_so_local.pack(fill=tk.X, pady=3)

        self.btn_so_local = ttk.Button(control_frame, text="SO Remoto", command=lambda: self.thread_tarea(self.ejecutar_so_remoto))
        self.btn_so_local.pack(fill=tk.X, pady=3)

        self.btn_puertos = ttk.Button(control_frame, text="Escanear Puertos", command=lambda: self.thread_tarea(self.ejecutar_puertos))
        self.btn_puertos.pack(fill=tk.X, pady=3)

        self.btn_ping = ttk.Button(control_frame, text="Ping Sweep", command=lambda: self.thread_tarea(self.ejecutar_ping))
        self.btn_ping.pack(fill=tk.X, pady=3)

        self.botones = [self.btn_so_local, self.btn_so_local, self.btn_puertos, self.btn_ping]

        # === RESULTADOS ===
        self.resultado_text = scrolledtext.ScrolledText(
            result_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#1e1e1e",
            fg="#00ff88",
            insertbackground="white"
        )
        self.resultado_text.pack(fill=tk.BOTH, expand=True)

        ttk.Button(result_frame, text="Limpiar", command=self.limpiar_resultados).pack(fill=tk.X, pady=5)

    def crear_entrada(self, parent, label_text, default=""):
        ttk.Label(parent, text=label_text).pack(anchor=tk.W)
        entry = ttk.Entry(parent)
        entry.insert(0, default)
        entry.pack(fill=tk.X, pady=3)
        return entry

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

    def ejecutar_so_local(self):
        self.limpiar_resultados()
        self.mostrar_resultado("=== Identificando SO Local ===")
        so = platform.platform()
        self.mostrar_resultado(f"Sistema Operativo Local: {so}")

    def ejecutar_so_remoto(self):
        host = self.entry_host.get().strip()
        if not scanner.validar_ip(host):
            self.mostrar_resultado("Error: Dirección IP inválida.")
            return
        self.limpiar_resultados()
        self.mostrar_resultado(f"=== Identificando SO Remoto en {host} ===")
        scanner.fingerprint_os(host, self.mostrar_resultado)

    def ejecutar_puertos(self):
        host = self.entry_host.get().strip()
        puertos_str = self.entry_puertos.get().strip()

        if not scanner.validar_ip(host):
            self.mostrar_resultado("Error: Dirección IP inválida.")
            return

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
        subred = self.entry_subred.get().strip()
        if not scanner.validar_subred(subred):
            self.mostrar_resultado("Error: Subred inválida.")
            return

        self.limpiar_resultados()
        self.mostrar_resultado(f"=== Realizando Ping Sweep en {subred} ===")
        scanner.ping_sweep(subred, self.mostrar_resultado)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
