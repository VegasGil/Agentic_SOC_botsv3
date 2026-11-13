import pytest
from jarvis import procesar_alertas

def test_jarvis_router_mock(mocker):
    # Alertas de prueba
    mock_alerts = [
        {"id": "1", "computerDnsName": "falex", "title": "XMRig Malware"},
        {"id": "2", "computerDnsName": "soc-appserver-01", "title": "CVE-2024-1234"},
        {"id": "3", "computerDnsName": "pc-01", "title": "Equipos Zombie"}
    ]
    
    # Simulamos lectura de archivos
    mocker.patch("jarvis.os.path.exists", return_value=True)
    mocker.patch("jarvis.open", mocker.mock_open(read_data="[]"), create=True)
    mocker.patch("jarvis.json.load", side_effect=[mock_alerts, []])
    mocker.patch("jarvis.json.dump")
    mocker.patch("jarvis.fetch_splunk_alerts")
    
    # Simulamos los ejecutores de los agentes
    mock_friday = mocker.patch("jarvis.ejecutar_friday")
    mock_friday.return_value = "Informe Friday"
    mock_edith = mocker.patch("jarvis.ejecutar_edith")
    mock_edith.return_value = "Informe Edith"
    mock_karen = mocker.patch("jarvis.ejecutar_karen")
    mock_karen.return_value = "Informe Karen"

    # Mockeamos Visión para que decida los agentes
    mock_crew_class = mocker.patch("jarvis.Crew")
    mock_crew_instance = mock_crew_class.return_value
    mock_crew_instance.kickoff.side_effect = [
        mocker.Mock(raw="FRIDAY"), 
        mocker.Mock(raw="KAREN"), 
        mocker.Mock(raw="EDITH")
    ]

    # Ejecutamos
    procesar_alertas()

    # Verificamos que cada agente se llamó 1 vez
    assert mock_friday.call_count == 1
    assert mock_karen.call_count == 1
    assert mock_edith.call_count == 1