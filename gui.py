import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import scanner

# Función para mostrar resultados
def mostrar_resultado(texto):
    output.insert(tk.END, texto + "\n")
    output.see(tk.END)

# Funciones conectadas a los botones
def escanear_red():
    red = simpledialog.askstring("Subred", "Ingresa la subred (ej. 192.168.1.0/24):")
    if red:
        activos = scanner.ping_sweep(red)
        mostrar_resultado(f"Hosts activos: {activos}")

def escanear_puertos():
    host = simpledialog.askstring("IP", "Ingresa la IP del host:")
    if not host:
        return
    rango = simpledialog.askstring("Rango de Puertos", "Ejemplo: 20-80")
    if not rango:
        return
    try:
        inicio, fin = map(int, rango.split('-'))
        if inicio < 0 or fin > 65535 or inicio > fin:
            raise ValueError
        puertos = range(inicio, fin + 1)
        resultado = scanner.port_scan(host, puertos)
        for port, banner in resultado:
            mostrar_resultado(f"Puerto {port} abierto - Banner: {banner}")
    except:
        messagebox.showerror("Error", "Rango de puertos inválido")

def identificar_so_remoto():
    host = simpledialog.askstring("IP", "Ingresa la IP del host remoto:")
    if host:
        scanner.fingerprint_os(host)

def identificar_so_local():
    scanner.identificar_sistema_operativo()

# Crear ventana principal
ventana = tk.Tk()
ventana.title("Escáner de Red Avanzado")
ventana.geometry("600x500")

# Etiqueta de título
titulo = tk.Label(ventana, text="Escáner de Red", font=("Arial", 16, "bold"))
titulo.pack(pady=10)

# Botones de opciones
btn_red = tk.Button(ventana, text="🔍 Escanear Red", width=30, command=escanear_red)
btn_red.pack(pady=5)

btn_puertos = tk.Button(ventana, text="📡 Escanear Puertos", width=30, command=escanear_puertos)
btn_puertos.pack(pady=5)

btn_so_remoto = tk.Button(ventana, text="🧠 Identificar SO Remoto", width=30, command=identificar_so_remoto)
btn_so_remoto.pack(pady=5)

btn_so_local = tk.Button(ventana, text="🖥️ Identificar SO Local", width=30, command=identificar_so_local)
btn_so_local.pack(pady=5)

# Área para mostrar resultados
output = scrolledtext.ScrolledText(ventana, width=70, height=20)
output.pack(pady=10)

ventana.mainloop()
