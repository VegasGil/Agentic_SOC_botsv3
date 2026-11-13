import urllib.request
import json
import os
import ssl
import urllib3

# Desactivar advertencias de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URLS = {
    "attack.json": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "capec.json": "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json",
}

def descargar_archivo(nombre, url, ruta_destino):
    if os.path.exists(ruta_destino):
        print(f"✅ {nombre} ya existe. Saltando descarga.")
        return
    
    print(f"📥 Descargando {nombre}...")
    try:
        context = ssl._create_unverified_context()
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=context) as response:
            data = response.read()
            with open(ruta_destino, "wb") as f:
                f.write(data)
        print(f"✅ {nombre} descargado ({len(data) / 1024 / 1024:.1f} MB).")
    except Exception as e:
        print(f"❌ Error descargando {nombre}: {e}")

def descargar_intel():
    os.makedirs("aspm/data", exist_ok=True)
    
    # 1. Descargar MITRE ATT&CK y CAPEC
    for nombre, url in URLS.items():
        descargar_archivo(nombre, url, f"aspm/data/{nombre}")

    # 2. Descargar EPSS (Mantenemos tu lógica)
    print("📥 Descargando base de datos EPSS...")
    url_epss = "https://api.first.org/data/v1/epss"
    try:
        context = ssl._create_unverified_context()
        req = urllib.request.Request(url_epss, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=context) as response:
            data = json.loads(response.read().decode())
            epss_dict = {item["cve"]: float(item["epss"]) for item in data.get("data", [])}
            with open("aspm/data/epss.json", "w") as f:
                json.dump(epss_dict, f)
            print(f"✅ EPSS descargado ({len(epss_dict)} CVEs).")
    except Exception as e:
        print(f"❌ Error descargando EPSS: {e}")
        with open("aspm/data/epss.json", "w") as f:
            json.dump({"CVE-2021-44228": 0.97}, f)

    # 3. Descargar KEV
    print("📥 Descargando base de datos CISA KEV...")
    url_kev = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        context = ssl._create_unverified_context()
        req = urllib.request.Request(url_kev, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=context) as response:
            data = json.loads(response.read().decode())
            kev_list = [item["cveID"] for item in data.get("vulnerabilities", [])]
            with open("aspm/data/kev.json", "w") as f:
                json.dump(kev_list, f)
            print(f"✅ KEV descargado ({len(kev_list)} CVEs).")
    except Exception as e:
        print(f"❌ Error descargando KEV: {e}")
        with open("aspm/data/kev.json", "w") as f:
            json.dump(["CVE-2021-44228"], f)

if __name__ == "__main__":
    descargar_intel()