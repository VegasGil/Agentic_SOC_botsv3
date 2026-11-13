import pytest
from tools.phishing_tool import detectar_phishing

def test_phishing_success(mocker):
    mock_response = mocker.patch("requests.get")
    mock_response.return_value.status_code = 200
    mock_response.return_value.json.return_value = {
        "threat": True, "risk_score": 90, "severity": "High"
    }
    
    resultado = detectar_phishing.run("paypal-secure-login.xyz")
    assert "PHISHING DETECTADO" in resultado