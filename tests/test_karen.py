import pytest
from unittest.mock import MagicMock
from agents.karen import ejecutar_karen

def test_karen_rbvm_flow(mocker):
    # 1. Simulamos la nueva herramienta de búsqueda raw en Azure
    mock_fetch_cves = mocker.patch("agents.karen.fetch_cves_raw")
    mock_fetch_cves.run.return_value = '[{"CveId": "CVE-2021-44228", "SoftwareName": "log4j"}]'

    # 2. Simulamos la priorización
    mock_prioritize = mocker.patch("agents.karen.prioritize_cves")
    mock_prioritize.run.return_value = "Reporte técnico: Log4j es CRÍTICO."

    # 3. Simulamos la conexión a Ollama
    mock_openai_class = mocker.patch("agents.karen.OpenAI")
    mock_client = mock_openai_class.return_value
    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock(message=MagicMock(content="Informe ejecutivo: Parchear Log4j YA."))]
    mock_client.chat.completions.create.return_value = mock_completion

    # 4. Simulamos el envío a Splunk
    mock_send_verdict = mocker.patch("agents.karen.send_verdict")
    mock_send_verdict.run.return_value = "✅ Veredicto indexado en Splunk."

    # 5. Ejecutamos
    resultado = ejecutar_karen("soc-appserver-01", "infraestructura")

    # 6. Verificamos
    assert "Informe ejecutivo: Parchear Log4j YA." in resultado
    mock_fetch_cves.run.assert_called_once_with("soc-appserver-01")
    mock_prioritize.run.assert_called_once()
    mock_client.chat.completions.create.assert_called_once()
    mock_send_verdict.run.assert_called_once_with("Informe ejecutivo: Parchear Log4j YA.", "K.A.R.E.N.")