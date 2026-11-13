import json
import os
from crewai.tools import tool

@tool("Priorizar CVEs con EPSS y KEV")
def prioritize_cves(cves_json: str) -> str:
    """Recibe un JSON de CVEs, las cruza con EPSS y CISA KEV, y devuelve un informe priorizado."""
    print("   -> [K.A.R.E.N.] Enriqueciendo CVEs con EPSS y KEV...")
    
    try:
        # Intentamos parsear el JSON. Si es un texto, buscamos el array.
        if isinstance(cves_json, str):
            start = cves_json.find('[')
            end = cves_json.rfind(']') + 1
            if start != -1 and end != 0:
                cves = json.loads(cves_json[start:end])
            else:
                return "Error: No se encontró un array JSON en el texto."
        else:
            cves = cves_json
    except Exception as e:
        return f"Error al parsear CVEs: {e}"

    # Cargar bases de datos locales (asumiendo que están en aspm/data/)
    epss_db = {}
    kev_db = set()
    
    try:
        if os.path.exists("aspm/data/epss.json"):
            with open("aspm/data/epss.json", "r") as f:
                epss_db = json.load(f)
        if os.path.exists("aspm/data/kev.json"):
            with open("aspm/data/kev.json", "r") as f:
                kev_db = set(json.load(f))
    except Exception as e:
        return f"Error al cargar bases de datos locales: {e}"

    # Enriquecer
    priorizadas = []
    for cve in cves:
        cve_id = cve.get("CveId")
        if not cve_id:
            continue
        
        epss_score = epss_db.get(cve_id, 0.0)
        in_kev = cve_id in kev_db
        
        # Lógica de priorización (basada en la industria)
        if in_kev:
            prioridad = "CRÍTICA (En CISA KEV)"
            accion = "Parchear INMEDIATAMENTE (24h)."
        elif epss_score >= 0.5:
            prioridad = "ALTA (EPSS Alto)"
            accion = "Parchear esta semana."
        elif epss_score >= 0.1:
            prioridad = "MEDIA (EPSS Moderado)"
            accion = "Programar parcheo."
        else:
            prioridad = "BAJA (Baja probabilidad)"
            accion = "Revisar en el próximo ciclo."

        priorizadas.append({
            "cve": cve_id,
            "paquete": cve.get("SoftwareName"),
            "severidad_base": cve.get("VulnerabilitySeverityLevel"),
            "epss": epss_score,
            "en_kev": in_kev,
            "prioridad": prioridad,
            "accion": accion
        })

    # Ordenar por prioridad (KEV primero, luego EPSS)
    priorizadas.sort(key=lambda x: (not x["en_kev"], -x["epss"]))

    # Crear resumen
    resumen = "CVEs encontradas y priorizadas:\n"
    for p in priorizadas:
        resumen += f"- {p['cve']} en {p['paquete']} (Sev: {p['severidad_base']}). EPSS: {p['epss']:.2f}. KEV: {'SÍ' if p['en_kev'] else 'No'}. Prioridad: {p['prioridad']}. Acción: {p['accion']}\n"

    return resumen