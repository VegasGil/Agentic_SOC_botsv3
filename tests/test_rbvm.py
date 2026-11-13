import sys
import os

# Esto le dice a Python que busque desde la raíz del proyecto
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.rbvm_enricher import prioritize_cves

def test_rbvm():
    print("🧪 Probando el motor RBVM...")
    
    # Simulamos la salida que vendría de Defender (Azure)
    cves_simuladas = '''
    [
        {"CveId": "CVE-2024-1234", "SoftwareName": "libpcre2", "VulnerabilitySeverityLevel": "High"},
        {"CveId": "CVE-2021-44228", "SoftwareName": "log4j", "VulnerabilitySeverityLevel": "Critical"}
    ]
    '''
    
    # Ejecutamos la herramienta
    reporte = prioritize_cves.run(cves_simuladas)
    
    print("\n=== 📊 REPORTE DE PRIORIZACIÓN ===")
    print(reporte)

if __name__ == "__main__":
    test_rbvm()