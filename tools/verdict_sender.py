import os
import json
import requests
import urllib3
from crewai.tools import tool
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@tool("Enviar Veredicto a Splunk")
def send_verdict(verdict_json: str, source_name: str) -> str:
    """Envía el veredicto final de un agente a Splunk usando HEC."""
    
    # 🚨 1. Leemos la URL completa del .env (con el puerto que sea)
    splunk_hec_url = os.getenv("SPLUNK_HEC_URL")
    splunk_token = os.getenv("SPLUNK_HEC_TOKEN") or os.getenv("HEC_TOKEN")
    
    if not splunk_hec_url or not splunk_token:
        return "Error: Faltan credenciales (SPLUNK_HEC_URL o HEC_TOKEN) en el .env"

    url = splunk_hec_url
    headers = {"Authorization": f"Splunk {splunk_token}"}
    
    # Intentamos parsear el JSON. Si es texto, lo enviamos como string.
    try:
        event_data = json.loads(verdict_json) if verdict_json.strip().startswith("{") else {"report": verdict_json}
    except:
        event_data = {"report": verdict_json}

    event_data["source_agent"] = source_name
    
    payload = {
        "event": event_data,
        "sourcetype": "nirvana:secops:verdict"
    }

    try:
        r = requests.post(url, json=payload, headers=headers, verify=False, timeout=10)
        r.raise_for_status()
        return f"✅ Veredicto de {source_name} indexado en Splunk."
    except Exception as e:
        return f"❌ Error enviando a Splunk: {e}"