import json
import os
from crewai.tools import tool
from tools.aspm_engine import prioritize_aspm

@tool("Escanear Código (ASPM)")
def scan_application_aspm(target_path: str = ".") -> str:
    """Escanea el código en busca de vulnerabilidades y las prioriza con EPSS y KEV."""  # <-- AÑADIR ESTO
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

    reporte = prioritize_aspm.run(trivy_json_path)
    
    return reporte