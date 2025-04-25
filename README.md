# 🔍 Network Scanner GUI

Una herramienta gráfica desarrollada en Python con `tkinter` para escanear redes, detectar puertos abiertos, hacer ping sweeps, y obtener información del sistema operativo (local y remoto). Todo desde una interfaz grafica con tema oscuro.

##  Descripción del proyecto

Este escáner de red fue diseñado para ser simple, rápido y visualmente amigable. Sus principales características son:

- Detección del sistema operativo local
- Identificación remota de SO usando TTL
- Escaneo de puertos (individuales, rangos o múltiples específicos)
- Ping Sweep en subredes completas
- Interfaz moderna con tema oscuro
- Resultados en tiempo real sin bloquear la interfaz


# Requisitos

- Python 3.7 o superior
- Sistema operativo compatible: Windows, Linux, macOS

# Instalación de dependencias

- pip install scapy (libreria a descargar)

###  Librerías utilizadas (todas estándar en Python)

- tkinter  
- socket  
- platform  
- threading, multiprocessing, concurrent.futures  
- ipaddress, subprocess, os

  No es necesario instalar paquetes adicionales. Todo funciona con librerías estándar de Python.


 # Crear un ejecutable para Windows
 
 Se debe instalar en una terminal primero "pip install pyinstaller" y luego dentro de la carpeta que lo contenga en este caso "repositorioRedes2 y ejecutar una terminal dentro de la carpeta el comando "pyinstaller --noconsole --onefile Prono02.py"

 - pip install pyinstaller
 - pyinstaller --onefile Proto02.py

   El ejecutable se encontrará en la carpeta dist/ y funcionará de manera independiente.

   en nuestro caso se almacenara en (C:\Users\Diego\RedesA\repositorioRedes\dist)
   # Github
   en la carpeta Dist se encuentra el ejecutable.
   #  Ejemplos de uso
   
Al ejecutar el script, se vera un menu con opciones que son:
- 1.Escanear red para encontrar hosts activos
   se puede ingresar una red como: 192.168.1.0/24 o cualquiera que sea una red disponible local
  
- 2.Escanear puertos en un host específico
  Ingresa la IP del host y el rango de puertos como 192.168.1.181 y al realizarlo da la opcion de rangos de puerts a escanear
  ej: 0-1024 o si se quierre escanear todos 0-65535
  
- 3.Identificar sistema operativo remoto
  Proporciona la IP del objetivo para estimar su sistema operativo según TTL
  ej:192.168.1.181 y arrojara a que tipo de sistema operativo corresponde

  
  # 👥 Integrantes del equipo
  Raul Vergara – Codigo Base, Branches, repositorio Github.

  Diego Calderon – Mejoras adicionales a codigo segun necesidad, Readme, interfaz grafica.


