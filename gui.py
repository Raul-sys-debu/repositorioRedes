import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import platform
import scanner  # Asegúrate de que este módulo esté correcto

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Escáner de Red - Funcional")
        self.root.geometry("800x600")
        self.create_widgets()
    
    def create_widgets(self):
        # Configuración principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Panel de controles (izquierda)
        control_frame = ttk.LabelFrame(main_frame, text="Controles", padding="10")
        control_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        # Panel de resultados (derecha)
        result_frame = ttk.LabelFrame(main_frame, text="Resultados", padding="10")
        result_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # ===== CONTROLES =====
        # Entrada para host remoto
        ttk.Label(control_frame, text="Host Remoto:").pack(anchor=tk.W)
        self.entry_host = ttk.Entry(control_frame, width=20)
        self.entry_host.pack(fill=tk.X, pady=5)
        self.entry_host.insert(0, "192.168.1.1")
        
        # Entrada para puertos
        ttk.Label(control_frame, text="Puertos (ej: 80,443):").pack(anchor=tk.W)
        self.entry_puertos = ttk.Entry(control_frame, width=20)
        self.entry_puertos.pack(fill=tk.X, pady=5)
        self.entry_puertos.insert(0, "80,443")
        
        # Entrada para subred
        ttk.Label(control_frame, text="Subred (ej: 192.168.1.0/24):").pack(anchor=tk.W)
        self.entry_subred = ttk.Entry(control_frame, width=20)
        self.entry_subred.pack(fill=tk.X, pady=5)
        self.entry_subred.insert(0, "192.168.1.0/24")
        
        # Botones
        ttk.Button(control_frame, text="SO Local", 
                 command=lambda: threading.Thread(target=self.ejecutar_so_local).start()).pack(fill=tk.X, pady=5)
        
        ttk.Button(control_frame, text="SO Remoto", 
                 command=lambda: threading.Thread(target=self.ejecutar_so_remoto).start()).pack(fill=tk.X, pady=5)
        
        ttk.Button(control_frame, text="Escanear Puertos", 
                 command=lambda: threading.Thread(target=self.ejecutar_puertos).start()).pack(fill=tk.X, pady=5)
        
        ttk.Button(control_frame, text="Ping Sweep", 
                 command=lambda: threading.Thread(target=self.ejecutar_ping).start()).pack(fill=tk.X, pady=5)
        
        # ===== RESULTADOS =====
        self.resultado_text = scrolledtext.ScrolledText(
            result_frame, 
            wrap=tk.WORD,
            width=60,
            height=25,
            font=('Consolas', 10)
        )
        self.resultado_text.pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(result_frame, text="Limpiar", 
                 command=self.limpiar_resultados).pack(fill=tk.X, pady=5)
    
    def mostrar_resultado(self, texto):
        self.resultado_text.insert(tk.END, texto + "\n")
        self.resultado_text.see(tk.END)
        self.resultado_text.update_idletasks()
    
    def limpiar_resultados(self):
        self.resultado_text.delete(1.0, tk.END)
    
    def ejecutar_so_local(self):
        self.limpiar_resultados()
        self.mostrar_resultado("=== Identificando SO Local ===")
        try:
            so = platform.platform()
            self.mostrar_resultado(f"Sistema Operativo Local: {so}")
        except Exception as e:
            self.mostrar_resultado(f"Error: {str(e)}")
    
    def ejecutar_so_remoto(self):
        host = self.entry_host.get().strip()
        if not scanner.validar_ip(host):
            self.mostrar_resultado("Error: Dirección IP inválida. Solo se permiten IPv4 válidas.")
            return
        
        self.limpiar_resultados()
        self.mostrar_resultado(f"=== Identificando SO Remoto en {host} ===")
        try:
            scanner.fingerprint_os(host, self.mostrar_resultado)
        except Exception as e:
            self.mostrar_resultado(f"Error: {str(e)}")
    
    def ejecutar_puertos(self):
        host = self.entry_host.get().strip()
        puertos_str = self.entry_puertos.get().strip()

        if not scanner.validar_ip(host):
            self.mostrar_resultado("Error: Dirección IP inválida. Solo se permiten IPv4 válidas.")
            return

        try:
            puertos = [int(p) for p in puertos_str.split(",") if p.strip().isdigit()]
            if not puertos:
                raise ValueError
        except ValueError:
            self.mostrar_resultado("Error: Formato de puertos inválido. Usa números separados por comas (ej: 22,80,443)")
            return

        self.limpiar_resultados()
        self.mostrar_resultado(f"=== Escaneando puertos en {host} ===")
        try:
            scanner.port_scan(host, puertos, self.mostrar_resultado)
        except Exception as e:
            self.mostrar_resultado(f"Error: {str(e)}")
    
    def ejecutar_ping(self):
        subred = self.entry_subred.get().strip()
        if not scanner.validar_subred(subred):
            self.mostrar_resultado("Error: Subred inválida. Usa formato correcto (ej: 192.168.1.0/24)")
            return

        self.limpiar_resultados()
        self.mostrar_resultado(f"=== Realizando Ping Sweep en {subred} ===")
        try:
            scanner.ping_sweep(subred, self.mostrar_resultado)
        except Exception as e:
            self.mostrar_resultado(f"Error: {str(e)}")

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = NetworkScannerApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Error al iniciar la aplicación: {str(e)}")