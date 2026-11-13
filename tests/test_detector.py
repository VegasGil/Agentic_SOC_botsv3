import pytest
from unittest.mock import MagicMock
from agents.detector import ejecutar_detector

def test_detector_mock(mocker):
    # 1. Simulamos que el archivo YAML existe
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("builtins.open", mocker.mock_open(read_data="title: Test Rule"))

    # 2. Simulamos la herramienta de conversión (que ahora vive en tools/sigma_converter)
    mock_convert = mocker.patch("agents.detector.convert_sigma_to_kql")
    mock_convert.run.return_value = "DeviceProcessEvents | where CommandLine has 'test'"

    # 3. Ejecutamos la función del agente
    resultado = ejecutar_detector("ruta_falsa.yml")

    # 4. Verificamos que devuelve el KQL simulado y que llamó a la herramienta
    assert "DeviceProcessEvents" in resultado
    mock_convert.run.assert_called_once()