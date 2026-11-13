import pytest
from tools.virustotal_tool import consultar_virustotal

def test_virustotal_success(mocker):
    # 🚨 TRUCO: Simulamos que existe la variable de entorno para GitHub Actions
    mocker.patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "fake_api_key_for_ci"})
    
    # Simulamos la respuesta de la API
    mock_response = mocker.patch("requests.get")
    mock_response.return_value.status_code = 200
    mock_response.return_value.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 50}}}
    }
    
    resultado = consultar_virustotal.run("8.8.8.8")
    assert "5 motores lo marcan como malicioso" in resultado