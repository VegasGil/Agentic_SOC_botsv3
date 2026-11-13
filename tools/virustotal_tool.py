import os
import requests
from crewai.tools import tool
from dotenv import load_dotenv

load_dotenv()

@tool("Consultar Reputación en VirusTotal")
def consultar_virustotal(indicador: str) -> str:
    """Consulta la reputación de una IP, dominio o hash en VirusTotal."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return "Error: Falta VIRUSTOTAL_API_KEY en el .env"
    
    # Detectamos si es IP o Hash
    if indicador.count('.') == 3:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicador}"
    else:
        url = f"https://www.virustotal.com/api/v3/files/{indicador}"
        
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            return f"VirusTotal: {malicious} motores lo marcan como malicioso, {suspicious} como sospechoso, {harmless} como inofensivo."
        elif response.status_code == 404:
            return "VirusTotal: El indicador no tiene reportes previos (es nuevo o desconocido)."
        else:
            return f"Error en VirusTotal: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Error de conexión con VirusTotal: {e}"