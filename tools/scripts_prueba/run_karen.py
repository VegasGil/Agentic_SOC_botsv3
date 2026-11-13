import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.kql_runner import run_and_analyze

def test_karen():
    print("🛡️  Iniciando K.A.R.E.N. (Auditoría de Vulnerabilidades en Azure)...")
    
    # Python llama directo a la herramienta
    resultado = run_and_analyze.run(
        playbook_filename='vuln_cve_equipo.kql',
        equipo='falex',
        incidente='Auditoría de Vulnerabilidades'
    )
    
    print("\n=== 🧠 INFORME DE K.A.R.E.N. ===")
    print(resultado)

if __name__ == "__main__":
    test_karen()