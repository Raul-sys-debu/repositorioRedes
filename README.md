#  Escáner de una red local

Este proyecto en Python permite realizar un análisis avanzado de una red local. Las funcionalidades incluyen:
- Detección de hosts activos mediante *ping sweep*
- Escaneo de puertos con identificación de banners
- Fingerprinting (identificacion de sistrema remoto) del sistema operativo remoto basado en TTL
- Identificación del sistema operativo del host local
- Registro de resultados en un archivo "reporte.txt"


# Requisitos

- Python 3.7 o superior
- Sistema operativo compatible: Windows, Linux, macOS

# Instalación de dependencias

- pip install scapy (libreria a descargar)

 # Crear un ejecutable para Windows

 - pip install pyinstaller
 - pyinstaller --onefile ProtoNmap01.py

   en nuestro caso se almacenara en (C:\Users\Diego\RedesA\repositorioRedes\dist)

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
  Raul Vergara – Desarrollo de codigo

  Diego Calderon – Mejoras adicionales a codigo segun necesidad, Readme


