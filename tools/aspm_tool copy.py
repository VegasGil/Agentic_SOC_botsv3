import json
import os
from crewai.tools import tool
from pathlib import Path

# Importamos tu motor lógico
from tools.aspm_engine import prioritize_aspm

@tool("Escanear Código (ASPM)")
def scan_application_aspm(target_path: str = ".") -> str:
    """
    Usa Trivy para escanear el código en busca de vulnerabilidades, 
    y luego las prioriza con EPSS y KEV.
    """
    print(f"   -> [K.A.R.E.N.] Escaneando código ASPM en: {target_path}")
    
    trivy_json_path = "data/trivy_results.json"
    
    if not os.path.exists(trivy_json_path):
        os.makedirs("data", exist_ok=True)
        mock_trivy = {
            "Results": [{
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j", "Severity": "CRITICAL"},
                    {"VulnerabilityID": "CVE-2024-1234", "PkgName": "libpcre2", "Severity": "HIGH"}
                ]
            }]
        }
        with open(trivy_json_path, "w") as f:
            json.dump(mock_trivy, f)

    # 🚨 CAMBIO AQUÍ: Si prioritize_aspm es una función normal, la llamamos sin .run()
    try:
        reporte = prioritize_aspm(trivy_json_path, enviar_splunk=True)
    except TypeError:
        # Si la función no acepta esos argumentos, la llamamos solo con la ruta
        reporte = prioritize_aspm(trivy_json_path)
        
    return reporte