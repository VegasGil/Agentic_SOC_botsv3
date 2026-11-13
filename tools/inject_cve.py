import requests
import json
import os
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEC_TOKEN = os.getenv("HEC_TOKEN")
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://82.70.86.75")

# Aseguramos que tenga el protocolo
if not SPLUNK_HOST.startswith("http"):
    SPLUNK_HOST = f"https://{SPLUNK_HOST}"

# Simulamos una alerta de Defender avisando de una CVE
fake_cve_alert = {
    "id": "fake-cve-alert-9999",
    "incidentId": 9999,
    "severity": "High",
    "status": "New",
    "category": "Vulnerability",
    "title": "Critical CVE-2024-21412 detected on device",
    "description": "A critical vulnerability in the operating system was detected. Immediate patching is required.",
    "computerDnsName": "soc-appserver-01",
    "threatName": "CVE-2024-21412"
}

payload = {
    "event": fake_cve_alert,
    "sourcetype": "ms:defender:atp:alerts"
}

url = f"{SPLUNK_HOST}:8088/services/collector/event"
headers = {"Authorization": f"Splunk {HEC_TOKEN}"}

try:
    r = requests.post(url, json=payload, headers=headers, verify=False)
    if r.status_code == 200:
        print("✅ Alerta CVE falsa inyectada en Splunk exitosamente.")
        print("Ahora ejecuta: python jarvis.py")
    else:
        print(f"❌ Error: {r.text}")
except Exception as e:
    print(f"❌ Error de conexión: {e}")