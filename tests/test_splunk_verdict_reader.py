import pytest
from tools.splunk_verdict_reader import ejecutar_consulta_spl

def test_ejecutar_consulta_spl_modo_demo():
    """Verifica que el lector funcione en modo demo o devuelva datos reales de Splunk."""
    resultado = ejecutar_consulta_spl.run(query_spl='search index=main "test"')
    
    # Si está en modo demo, debe decirlo
    if "Modo demo" in resultado:
        assert "Modo demo" in resultado
    # Si está conectado a Splunk real, debe devolver resultados (incluso si no encuentra nada)
    else:
        assert "Splunk devolvió" in resultado or "No se encontraron resultados" in resultado