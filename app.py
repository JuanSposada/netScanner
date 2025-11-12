# app.py

import nmap
from flask import Flask, render_template, request, jsonify
import json
import time

app = Flask(__name__)

# Diccionario global para mantener el estado de los dispositivos.
# Simula una base de datos simple.
# { "IP": {"nombre": "hostname", "mac": "mac_addr", "estado": "ACTIVO", "veces_ausente": 0} }
DISPOSITIVOS_CONOCIDOS = {}
RANGO_ACTUAL = "192.168.1.0/24" # Valor por defecto, se puede cambiar desde el frontend

# --- Lógica de Escaneo ---

def escanear_red(rango_cidr):
    """
    Ejecuta un escaneo Nmap para obtener IP, Nombre de Host y MAC.
    Retorna una lista de dispositivos activos.
    """
    nm = nmap.PortScanner()
    
    # -sn: Ping Scan (solo detección de host, no escanea puertos)
    # -PR: ARP Ping (más fiable para obtener MAC en LAN)
    # --system-dns: Usa el resolver DNS del sistema para nombres de host
    print(f"Iniciando escaneo de rango: {rango_cidr}...")
    
    try:
        # Nota: El path de Nmap es detectado automáticamente si está en el PATH de Windows.
        # Si tienes problemas, puedes especificarlo: nm.scan(..., nmap_path='C:/Program Files (x86)/Nmap/nmap.exe')
        nm.scan(hosts=rango_cidr, arguments='-sn -PR --system-dns')
    except nmap.PortScannerError as e:
        print(f"Error al ejecutar Nmap: {e}")
        return []
    
    dispositivos_activos = []
    
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            # Intentar obtener MAC y Nombre de Host
            mac = nm[host]['addresses'].get('mac', 'N/A')
            hostname = nm[host].hostname() or 'Desconocido'
            
            dispositivos_activos.append({
                "ip": host,
                "nombre": hostname,
                "mac": mac
            })
            
    print(f"Escaneo completado. Encontrados {len(dispositivos_activos)} dispositivos activos.")
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
            # Nueva dirección IP: Se agrega (Verde)
            DISPOSITIVOS_CONOCIDOS[ip] = {
                "nombre": dev_nuevo['nombre'],
                "mac": dev_nuevo['mac'],
                "estado": "ACTIVO",
                "veces_ausente": 0
            }
        else:
            # IP ya conocida: Se reactiva si estaba ausente (Verde)
            DISPOSITIVOS_CONOCIDOS[ip]["estado"] = "ACTIVO"
            DISPOSITIVOS_CONOCIDOS[ip]["veces_ausente"] = 0
            # Actualizamos nombre/mac por si cambió
            DISPOSITIVOS_CONOCIDOS[ip]["nombre"] = dev_nuevo['nombre']
            DISPOSITIVOS_CONOCIDOS[ip]["mac"] = dev_nuevo['mac']

    # --- Paso 2: Procesar Desaparecidos (Lógica de Grises y Eliminación) ---
    ips_a_eliminar = []
    for ip, data in list(DISPOSITIVOS_CONOCIDOS.items()):
        if ip not in ips_actuales:
            # La IP no respondió en este escaneo
            data['veces_ausente'] += 1
            
            if data['veces_ausente'] == 1:
                # Primera vez que no responde (Gris)
                data['estado'] = "AUSENTE_UNA_VEZ"
            
            elif data['veces_ausente'] >= 2:
                # Segunda vez consecutiva que no responde (Desaparece)
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
    # Usamos host 0.0.0.0 para que sea accesible en tu red local si es necesario
    app.run(host='0.0.0.0', port=5000, debug=True)