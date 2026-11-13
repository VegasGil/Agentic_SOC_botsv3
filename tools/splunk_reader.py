import os
import json
import requests
import urllib3
from crewai.tools import tool
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@tool("Obtener Alertas Nuevas de Splunk")
def fetch_splunk_alerts() -> str:
    """Conecta a Splunk, descarga alertas de Defender o de BOTS v3 y las guarda en data/splunk_alerts.json."""
    load_dotenv()
    print("   -> [Splunk] Buscando alertas en el servidor...")

    splunk_host = os.getenv("SPLUNK_HOST")
    splunk_port = os.getenv("SPLUNK_REST_PORT", "8089")
    splunk_user = os.getenv("SPLUNK_USER", "admin")
    splunk_pass = os.getenv("SPLUNK_PASS")

    if not splunk_host or not splunk_pass:
        return "Error: Faltan credenciales de Splunk en el .env"

    if not splunk_host.startswith("http"):
        splunk_host = f"https://{splunk_host}"

    url = f"{splunk_host}:{splunk_port}/services/search/jobs/export"
    
    # 🚨 CONSULTA MODIFICADA: Buscamos en BOTS v3 o en Defender
    # Intentamos traer eventos de los últimos 7 días en cualquier índice
    query = 'search (index=botsv3 OR index=main) | head 5'
    
    data = {
        "search": query,
        "output_mode": "json",
        "earliest_time": "-7d",
        "latest_time": "now",
    }

    try:
        response = requests.post(
            url, data=data, auth=(splunk_user, splunk_pass), verify=False, timeout=30
        )
        response.raise_for_status()
        alerts = []
        for line in response.text.splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            if "result" in obj:
                # Intentamos parsear el JSON del resultado
                try:
                    raw_data = obj["result"].get("_raw", "{}")
                    # Si es un JSON válido, lo agregamos
                    if raw_data.strip().startswith("{"):
                        alerts.append(json.loads(raw_data))
                    else:
                        # Si es texto plano (como los logs de BOTS v3), lo guardamos como un título
                        alerts.append({
                            "id": obj["result"].get("_cd", "unknown"),
                            "title": raw_data[:100],
                            "description": raw_data,
                            "computerDnsName": obj["result"].get("host", "BOTS v3")
                        })
                except Exception:
                    pass

        os.makedirs("data", exist_ok=True)
        with open("data/splunk_alerts.json", "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=4)
        
        if len(alerts) == 0:
            return "No se encontraron eventos en los últimos 7 días."
            
        return f"Se encontraron {len(alerts)} eventos. Guardados en data/splunk_alerts.json."
        
    except Exception as e:
        return f"Error conectando a Splunk: {e}"