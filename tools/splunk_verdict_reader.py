import os
import json
import requests
import re
from crewai.tools import tool
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@tool("Ejecutar Consulta en Splunk")
def ejecutar_consulta_spl(query_spl: str = "", fecha_filtro: str = "") -> str:
    """Ejecuta una consulta SPL dinámica en Splunk."""
    
    host = os.getenv("SPLUNK_HOST", "demo")
    port = os.getenv("SPLUNK_REST_PORT", "8089")
    user = os.getenv("SPLUNK_USER", "admin")
    password = os.getenv("SPLUNK_PASS", "")
    
    if host == "demo" or not host:
        return "Modo demo: no hay datos reales en Splunk."
    
    # ==========================================================
    # CONSTRUCCIÓN DE LA CONSULTA (siempre asigna 'consulta')
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
    # LLAMADA A SPLUNK
    # ==========================================================
    url = f"https://{host}:{port}/services/search/jobs/export"
    data = {"search": consulta, "output_mode": "json"}
    
    try:
        response = requests.post(url, data=data, auth=(user, password), verify=False, timeout=15)
        response.raise_for_status()
        
        resultados_texto = ""
        contador = 0
        
        for line in response.text.splitlines():
            if line.strip():
                try:
                    obj = json.loads(line)
                    if "result" in obj:
                        raw = obj["result"].get("_raw", "")
                        tiempo = obj["result"].get("_time", "Fecha desconocida")
                        
                        try:
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
                            else:
                                agente = "Desconocido"
                                reporte = raw
                        except:
                            agente = "Desconocido"
                            reporte = raw
                        
                        resultados_texto += f"\n--- Resultado {contador+1} ---\n"
                        resultados_texto += f"Fecha: {tiempo} | Agente: {agente}\n"
                        resultados_texto += f"{reporte}\n"
                        contador += 1
                except:
                    pass
        
        if contador == 0:
            return "No se encontraron resultados para esa consulta."
            
        return f"✅ Splunk devolvió {contador} resultados:\n{resultados_texto}"
        
    except Exception as e:
        return f"Error al consultar Splunk: {e}"