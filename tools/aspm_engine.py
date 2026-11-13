import sys
import os
import json
import urllib.request
import ssl
from pathlib import Path
from crewai.tools import tool

# Rutas
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "aspm" / "data"
EPSS_JSON = DATA_DIR / "epss.json"
KEV_JSON = DATA_DIR / "kev.json"

SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "UNKNOWN": 0}

@tool("Priorizar Vulnerabilidades ASPM")
def prioritize_aspm(trivy_json_path: str, enviar_splunk: bool = False) -> str:
    """Toma un archivo JSON de Trivy, calcula el riesgo real con EPSS/KEV y envía a Splunk si se solicita."""
    print("   -> [ASPM] Calculando riesgo de vulnerabilidades...")
    
    # 1. Verificar bases de datos
    if not EPSS_JSON.exists() or not KEV_JSON.exists():
        return "Error: Faltan bases de datos EPSS/KEV."

    try:
        epss_db = json.loads(EPSS_JSON.read_text())
        kev_db = set(json.loads(KEV_JSON.read_text()))
        trivy_data = json.loads(Path(trivy_json_path).read_text(encoding="utf-8-sig"))
    except Exception as e:
        return f"Error leyendo archivos: {e}"

    # 2. Calcular riesgo
    findings = []
    for result in trivy_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve = vuln.get("VulnerabilityID")
            pkg = vuln.get("PkgName")
            sev = vuln.get("Severity", "UNKNOWN")
            
            epss_val = epss_db.get(cve, 0.0)
            in_kev = cve in kev_db
            
            base = SEVERITY_WEIGHT.get(sev.upper(), 0)
            risk_score = base + (epss_val * 10) + (20 if in_kev else 0)
            
            findings.append({
                "cve": cve, "package": pkg, "severity": sev,
                "epss": round(epss_val, 3), "kev": in_kev, "risk_score": round(risk_score, 1)
            })

    findings.sort(key=lambda x: x["risk_score"], reverse=True)

    # 3. Formatear salida
    reporte = "=== RANKING DE RIESGO (ASPM) ===\n"
    for f in findings:
        reporte += f"[{f['risk_score']}] {f['cve']} en {f['package']} (Sev: {f['severity']}, EPSS: {f['epss']}, KEV: {'SÍ' if f['kev'] else 'No'})\n"

    # 4. Enviar a Splunk (solo si estamos en local)
    if enviar_splunk:
        print("   -> Enviando resultados a Splunk...")
        splunk_host = os.getenv("SPLUNK_HOST")
        splunk_token = os.getenv("SPLUNK_TOKEN")
        
        if not splunk_host or not splunk_token:
            reporte += "\n⚠️ No se configuraron SPLUNK_HOST o SPLUNK_TOKEN. Saltando envío."
        else:
            url = f"https://{splunk_host}:8088/services/collector/event"
            for f in findings[:5]: # Enviamos el top 5
                payload = {"event": f, "sourcetype": "aspm_prioritized"}
                req = urllib.request.Request(url, method="POST")
                req.add_header("Authorization", f"Splunk {splunk_token}")
                req.add_header("Content-Type", "application/json")
                context = ssl._create_unverified_context()
                try:
                    with urllib.request.urlopen(req, data=json.dumps(payload).encode(), context=context) as response:
                        pass
                except Exception as e:
                    reporte += f"\n❌ Error enviando a Splunk: {e}"

    return reporte # <-- AQUÍ FALTABA EL RETURN Y EL CIERRE