import os
from crewai.tools import tool
from anyrun.connectors import SandboxConnector

@tool("Analizar Hash en ANY.RUN Sandbox")
def analizar_anyrun(hash_file: str) -> str:
    """Sube un hash de archivo a ANY.RUN para análisis dinámico."""
    api_key = os.getenv("ANYRUN_API_KEY")
    if not api_key:
        return "Error: Falta ANYRUN_API_KEY en el .env"
    
    try:
        # ANY.RUN SDK requiere el archivo o URL, no el hash directo para sandbox.
        # Para hash, se usa la API de TI Lookup (más avanzada).
        # Aquí simulamos el flujo de búsqueda de reporte por hash.
        with SandboxConnector.windows(api_key) as connector:
            # Nota: El SDK de sandbox sube archivos, para buscar por hash se usa TI Lookup
            # Si no tienes el archivo, el flujo correcto es usar la API de TI Lookup.
            # Para este ejemplo, devolvemos un mensaje instructivo.
            return f"ANY.RUN: Para buscar el hash {hash_file}, usa la API de TI Lookup en la nube."
    except Exception as e:
        return f"Error en ANY.RUN: {e}"
    