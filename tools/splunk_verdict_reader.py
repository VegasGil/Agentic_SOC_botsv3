import os
import json
import requests
import re
from crewai.tools import tool
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@tool("Ejecutar Consulta en Splunk")
def ejecutar_consulta_spl(query_spl: str = "", fecha_filtro: str = "") -> str:
    """Ejecuta una consulta SPL dinámica en Splunk y formatea los resultados (JSON, Tablas, Texto)."""
    
    host = os.getenv("SPLUNK_HOST", "demo")
    port = os.getenv("SPLUNK_REST_PORT", "8089")
    user = os.getenv("SPLUNK_USER", "admin")
    password = os.getenv("SPLUNK_PASS", "")
    
    if host == "demo" or not host:
        return "Modo demo: no hay datos reales en Splunk."
    
    # ==========================================================
    # 1. CONSTRUCCIÓN DE LA CONSULTA
    # ==========================================================
    if fecha_filtro:
        partes = fecha_filtro.split('-')
        if len(partes) == 3:
            fecha_splunk = f"{partes[1]}/{partes[2]}/{partes[0]}"
        else:
            fecha_splunk = fecha_filtro
        consulta = f'search index=main earliest="{fecha_splunk}:00:00:00" latest="{fecha_splunk}:23:59:59" | head 50'
    elif query_spl:
        consulta = query_spl
    else:
        consulta = 'search index=main | head 20'
    
    print(f"   [SPLUNK] Ejecutando: {consulta}")
    
    # ==========================================================
    # 2. LLAMADA A SPLUNK
    # ==========================================================
    url = f"https://{host}:{port}/services/search/jobs/export"
    data = {"search": consulta, "output_mode": "json"}
    
    try:
        response = requests.post(url, data=data, auth=(user, password), verify=False, timeout=15)
        response.raise_for_status()
        
        resultados_texto = ""
        contador = 0
        
        for line in response.text.splitlines():
            if not line.strip():
                continue
                
            try:
                obj = json.loads(line)
                if "result" not in obj:
                    continue
                    
                resultado = obj["result"]
                raw = resultado.get("_raw", "")
                tiempo = resultado.get("_time", "Fecha desconocida")
                
                # ==========================================================
                # 3. LÓGICA DE FORMATO (BLINDADA)
                # ==========================================================
                agente = "Desconocido"
                reporte = ""
                
                # Caso A: Es una tabla de stats (no tiene _raw, tiene campos directos como "count" o "sourcetype")
                if not raw and len(resultado) > 1:
                    agente = "Splunk Analytics"
                    # Limpiamos los campos internos para que se vea bonito
                    datos_limpios = {k: v for k, v in resultado.items() if k not in ["_raw", "_time", "_indextime", "_cd", "index", "linecount", "punct", "splunk_server"]}
                    reporte = f"📊 Datos: {json.dumps(datos_limpios, indent=2)}"
                
                # Caso B: Tiene _raw (es un log normal)
                else:
                    try:
                        # Intentamos ver si el _raw es un JSON válido (como los eventos de Nirvana)
                        data_json = json.loads(raw)
                        
                        if "verdict" in data_json:
                            agente = data_json.get("source_agent", "Nirvana")
                            verdict = data_json.get("verdict", "N/A")
                            severity = data_json.get("severity", "N/A")
                            reason = data_json.get("reason", "Sin razón")
                            mitre = data_json.get("mitre_technique", "N/A")
                            reporte = (
                                f"🚨 VEREDICTO IA: {verdict.upper()} | Severidad: {severity.upper()}\n"
                                f"MITRE: {mitre}\n"
                                f"Razón: {reason}"
                            )
                        elif "source_agent" in data_json:
                            agente = data_json.get("source_agent", "Agente SOC")
                            reporte = data_json.get("report", raw)
                        elif "event_id" in data_json:
                            agente = "Nirvana (Evento original)"
                            reporte = (
                                f"📋 Evento: {data_json.get('event_id')}\n"
                                f"Summary: {data_json.get('summary', 'N/A')}\n"
                                f"IOC: {data_json.get('src', 'N/A')}"
                            )
                        elif "src_ip" in data_json or "dest_ip" in data_json:
                            # Eventos de red crudos (BOTS) que sí son JSON
                            agente = "Tráfico de Red"
                            reporte = json.dumps(data_json, indent=2)[:500] # Limitamos a 500 caracteres
                        else:
                            agente = "JSON Desconocido"
                            reporte = raw
                            
                    except json.JSONDecodeError:
                        # Caso C: El _raw es texto plano (logs clásicos de Sysmon, Apache, etc.)
                        agente = "Log de Texto"
                        reporte = raw
                
                # ==========================================================
                # 4. GUARDAR RESULTADO
                # ==========================================================
                resultados_texto += f"\n--- Resultado {contador+1} ---\n"
                resultados_texto += f"Fecha: {tiempo} | Tipo: {agente}\n"
                resultados_texto += f"{reporte}\n"
                contador += 1
                
            except json.JSONDecodeError:
                pass
            except Exception as e:
                # Si una línea individual falla, no rompemos todo el bucle
                continue
        
        if contador == 0:
            return "No se encontraron resultados para esa consulta."
            
        return f"✅ Splunk devolvió {contador} resultados:\n{resultados_texto}"
        
    except requests.exceptions.RequestException as e:
        return f"❌ Error de conexión con Splunk: {e}"
    except Exception as e:
        return f"❌ Error procesando la respuesta de Splunk: {e}"
    