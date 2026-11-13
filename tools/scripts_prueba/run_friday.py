import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.kql_runner import run_and_analyze

def test_friday():
    print("🕵️  Iniciando F.R.I.D.A.Y. (Investigación DFIR en Azure Defender)...")
    
    print("\n--- FASE 1: Identificación de Logins ---")
    resultado_logins = run_and_analyze.run(
        playbook_filename='dfir_fase1_identificacion.kql', 
        equipo='falex', 
        incidente='Logins Sospechosos'
    )
    print(resultado_logins)

    print("\n--- FASE 2: Ejecución de Procesos Maliciosos ---")
    resultado_procesos = run_and_analyze.run(
        playbook_filename='dfir_fase2_procesos.kql', 
        equipo='falex', 
        incidente='Ejecución de Malware (XMRig)'
    )
    print(resultado_procesos)

if __name__ == "__main__":
    test_friday()