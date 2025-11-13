# app.py - Monitor de Equipos en Red con Extracción de MAC Robusta (XML nativo)

import subprocess
import os
from flask import Flask, render_template, request, jsonify
# Importamos ElementTree para parsear el XML directamente
import xml.etree.ElementTree as ET 
import json
import time 

app = Flask(__name__)

# Diccionario global para mantener el estado de los dispositivos.
DISPOSITIVOS_CONOCIDOS = {}
RANGO_ACTUAL = "192.168.1.0/24" # Valor por defecto

# --- Lógica de Escaneo ---

def escanear_red(rango_cidr):
    """
    Ejecuta Nmap y procesa el resultado XML usando xml.etree.ElementTree para 
    extraer IP, Nombre y MAC de forma robusta, evitando errores de libnmap.
    """
    
    OUTPUT_FILE = 'nmap_scan_result.xml' 
    
    # Argumentos de Nmap: Mantenemos el timeout agresivo (500ms) y la resolución DNS (-R).
    NMAP_ARGS = [
        'nmap',
        '-sn',
        '-PR',
        '-T5',
        '-vv',
        '-R',
        '--host-timeout', '5000ms', 
        '-oX', OUTPUT_FILE, 
        rango_cidr
    ]

    print(f"\n=====================================================================")
    print(f"Iniciando escaneo de rango: {rango_cidr}. Progreso en tiempo real a continuación...")
    print(f"=====================================================================")
    
    try:
        # Ejecuta Nmap y captura la salida para el log
        process = subprocess.Popen(NMAP_ARGS, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        
        # Muestra la salida de Nmap en tiempo real mientras se ejecuta
        for line in process.stdout:
            print(line, end='')
        
        process.wait()
        
    except FileNotFoundError:
        print("\nERROR: El comando 'nmap' no fue encontrado. Asegúrate de que Nmap esté en el PATH de Windows.")
        return []
    except Exception as e:
        print(f"\nERROR durante la ejecución de Nmap: {e}")
        return []

    # --- PARSEAR RESULTADOS DEL ARCHIVO XML (USANDO XML.ETREE.ELEMENTTREE) ---
    dispositivos_activos = []
    
    if os.path.exists(OUTPUT_FILE):
        try:
            # 1. Leer el XML
            tree = ET.parse(OUTPUT_FILE)
            root = tree.getroot()
            
            # 2. Iterar sobre todos los hosts en el XML
            for host_element in root.findall('host'):
                
                # Verificar el estado del host (debe estar 'up')
                status_element = host_element.find('status')
                if status_element is None or status_element.get('state') != 'up':
                    continue

                ip = 'N/A'
                mac = 'N/A'
                hostname = 'Desconocido'
                
                # 3. Extraer IP y MAC de los elementos <address>
                for addr_element in host_element.findall('address'):
                    addr_type = addr_element.get('addrtype')
                    addr_value = addr_element.get('addr')
                    
                    if addr_type == 'ipv4':
                        ip = addr_value
                    elif addr_type == 'mac':
                        mac = addr_value
                
                # 4. Extraer Nombre de Host (si está disponible en <hostname>)
                hostnames_element = host_element.find('hostnames')
                if hostnames_element is not None:
                    # Tomar el primer nombre de host encontrado
                    hname_element = hostnames_element.find('hostname')
                    if hname_element is not None:
                        # Usar el atributo 'name' del tag
                        hostname = hname_element.get('name', 'Desconocido')
                
                # 5. Añadir a la lista si encontramos la IP
                if ip != 'N/A':
                    dispositivos_activos.append({
                        "ip": ip,
                        "nombre": hostname,
                        "mac": mac
                    })
            
        except Exception as e:
            # Captura errores genéricos de lectura o estructura del XML
            print(f"ERROR grave al parsear el resultado XML de Nmap usando ElementTree: {e}")
            
        finally:
            # Limpiar: eliminar el archivo XML temporal
            if os.path.exists(OUTPUT_FILE):
                os.remove(OUTPUT_FILE)
    else:
        print("ERROR: Archivo de salida XML no encontrado. El escaneo no generó resultados.")


    print(f"=====================================================================")
    print(f"Escaneo COMPLETADO. Encontrados {len(dispositivos_activos)} dispositivos activos.")
    print(f"=====================================================================\n")
    return dispositivos_activos


def actualizar_estado(nuevos_dispositivos):
    """
    Compara los resultados del escaneo actual con los dispositivos conocidos
    y actualiza el estado (ACTIVO, AUSENTE_UNA_VEZ, ELIMINADO).
    """
    global DISPOSITIVOS_CONOCIDOS
    
    ips_actuales = {d['ip'] for d in nuevos_dispositivos}
    
    # --- Paso 1: Procesar Activos y Nuevos ---
    for dev_nuevo in nuevos_dispositivos:
        ip = dev_nuevo['ip']
        if ip not in DISPOSITIVOS_CONOCIDOS:
            DISPOSITIVOS_CONOCIDOS[ip] = {
                "nombre": dev_nuevo['nombre'],
                "mac": dev_nuevo['mac'],
                "estado": "ACTIVO",
                "veces_ausente": 0
            }
        else:
            DISPOSITIVOS_CONOCIDOS[ip]["estado"] = "ACTIVO"
            DISPOSITIVOS_CONOCIDOS[ip]["veces_ausente"] = 0
            DISPOSITIVOS_CONOCIDOS[ip]["nombre"] = dev_nuevo['nombre']
            DISPOSITIVOS_CONOCIDOS[ip]["mac"] = dev_nuevo['mac']

    # --- Paso 2: Procesar Desaparecidos (Lógica de Grises y Eliminación) ---
    ips_a_eliminar = []
    for ip, data in list(DISPOSITIVOS_CONOCIDOS.items()):
        if ip not in ips_actuales:
            data['veces_ausente'] += 1
            
            if data['veces_ausente'] == 1:
                data['estado'] = "AUSENTE_UNA_VEZ"
            
            elif data['veces_ausente'] >= 2:
                ips_a_eliminar.append(ip)

    # Eliminar las IPs marcadas
    for ip in ips_a_eliminar:
        del DISPOSITIVOS_CONOCIDOS[ip]


# --- Rutas Flask (Backend API) ---

@app.route('/', methods=['GET'])
def index():
    """Ruta principal que sirve la página HTML."""
    global RANGO_ACTUAL
    return render_template('index.html', default_range=RANGO_ACTUAL)

@app.route('/scan', methods=['POST'])
def scan():
    """Ruta para ejecutar el escaneo y retornar los datos actualizados."""
    global RANGO_ACTUAL
    
    # 1. Obtener y actualizar el rango
    data = request.get_json()
    rango_cidr = data.get('rango', RANGO_ACTUAL)
    RANGO_ACTUAL = rango_cidr
    
    # 2. Ejecutar Nmap
    nuevos_dispositivos = escanear_red(rango_cidr)
    
    # 3. Actualizar el estado (Lógica de colores)
    actualizar_estado(nuevos_dispositivos)
    
    # 4. Preparar la respuesta JSON (solo los dispositivos que no se han eliminado)
    datos_a_mostrar = [
        {"ip": ip, "nombre": data['nombre'], "mac": data['mac'], "estado": data['estado']}
        for ip, data in DISPOSITIVOS_CONOCIDOS.items()
    ]
    
    return jsonify({"dispositivos": datos_a_mostrar, "rango_usado": RANGO_ACTUAL})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)