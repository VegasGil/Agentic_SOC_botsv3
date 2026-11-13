import requests
from crewai.tools import tool

@tool("Detectar Phishing en un Dominio")
def detectar_phishing(dominio: str) -> str:
    """Consulta el riesgo de phishing de un dominio usando la API gratuita de PhishDestroy."""
    # Limpiamos la URL para quedarnos solo con el dominio
    if "://" in dominio:
        dominio = dominio.split("://")[1].split("/")[0]
    
    url = f"https://api.destroy.tools/v1/check?domain={dominio}"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            
            # La API devuelve: threat (bool), risk_score (0-100), severity
            if data.get("threat"):
                score = data.get("risk_score", 0)
                severity = data.get("severity", "Desconocida")
                return f"🚨 PHISHING DETECTADO: El dominio '{dominio}' tiene un riesgo de {score}/100 (Severidad: {severity}). No hacer clic."
            else:
                return f"✅ El dominio '{dominio}' no está en la lista de Phishing de PhishDestroy."
        elif response.status_code == 404:
            return f"ℹ️ El dominio '{dominio}' no tiene reportes en PhishDestroy."
        else:
            return f"Error en PhishDestroy: {response.status_code}"
    except Exception as e:
        return f"Error de conexión con PhishDestroy: {e}"