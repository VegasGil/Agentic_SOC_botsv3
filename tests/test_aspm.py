import json
import os
from unittest.mock import patch
from tools.aspm_engine import prioritize_aspm
from pathlib import Path

def test_aspm_prioritization(tmp_path, mocker):
    # 1. Crear archivos de EPSS y KEV falsos en una carpeta temporal
    data_dir = tmp_path / "aspm" / "data"
    data_dir.mkdir(parents=True)
    
    epss_data = {"CVE-2021-44228": 0.97, "CVE-2024-1234": 0.02}
    kev_data = ["CVE-2021-44228"] # Log4j está en KEV
    
    (data_dir / "epss.json").write_text(json.dumps(epss_data))
    (data_dir / "kev.json").write_text(json.dumps(kev_data))

    # 2. Redirigir las rutas del motor para que usen los archivos temporales
    mocker.patch("tools.aspm_engine.EPSS_JSON", data_dir / "epss.json")
    mocker.patch("tools.aspm_engine.KEV_JSON", data_dir / "kev.json")

    # 3. Crear un archivo de Trivy falso
    trivy_data = {
        "Results": [{
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j", "Severity": "CRITICAL"},
                {"VulnerabilityID": "CVE-2024-1234", "PkgName": "libpcre2", "Severity": "HIGH"}
            ]
        }]
    }
    trivy_file = tmp_path / "trivy_results.json"
    trivy_file.write_text(json.dumps(trivy_data))

    # 4. Ejecutar el motor SIN enviar a Splunk
    resultado = prioritize_aspm.run(str(trivy_file), enviar_splunk=False)
    
    # 5. Verificar
    assert "CVE-2021-44228" in resultado
    assert "CVE-2024-1234" in resultado
    # Log4j debe tener mayor riesgo y estar primero
    pos_log4j = resultado.find("CVE-2021-44228")
    pos_libpcre = resultado.find("CVE-2024-1234")
    assert pos_log4j < pos_libpcre