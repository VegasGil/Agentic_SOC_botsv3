import json
import gzip
import urllib.request
import time
from pathlib import Path
from crewai.tools import tool

DATA_DIR = Path("aspm/data")

@tool("Actualizar Bases de Datos EPSS y KEV")
def update_threat_intel() -> str:
    """Actualiza EPSS y KEV si ha pasado más de 24h desde la última descarga. Si no, usa la caché."""
    print("   -> [K.A.R.E.N.] Verificando estado de las bases de datos...")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    epss_file = DATA_DIR / "epss.json"
    kev_file = DATA_DIR / "kev.json"
    now = time.time()
    one_day_seconds = 86400 # 24 horas

    # 1. Verificar si necesitan actualización
    needs_update = False
    if not epss_file.exists() or not kev_file.exists():
        needs_update = True
    else:
        epss_age = now - epss_file.stat().st_mtime
        kev_age = now - kev_file.stat().st_mtime
        if epss_age > one_day_seconds or kev_age > one_day_seconds:
            needs_update = True

    if not needs_update:
        return "✅ Base de datos al día (caché de menos de 24h). Usando datos locales."

    # 2. Si necesita actualización, descargar
    print("   -> [K.A.R.E.N.] Datos obsoletos o inexistentes. Descargando actualizaciones...")
    EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    try:
        # Descargar EPSS
        epss_dict = {}
        with urllib.request.urlopen(EPSS_URL, timeout=60) as resp:
            with gzip.open(resp, "rt", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("#") or line.startswith("cve,"): continue
                    parts = line.strip().split(",")
                    if len(parts) >= 2:
                        epss_dict[parts[0]] = float(parts[1])
        epss_file.write_text(json.dumps(epss_dict))
        
        # Descargar KEV
        with urllib.request.urlopen(KEV_URL, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        cves = {v["cveID"] for v in data.get("vulnerabilities", [])}
        kev_file.write_text(json.dumps(sorted(cves)))
        
        return f"✅ Bases actualizadas. EPSS: {len(epss_dict)} CVEs. KEV: {len(cves)} CVEs."
    except Exception as e:
        return f"❌ Error actualizando bases de datos: {e}"