import sys
from crewai.tools import tool

@tool("Traducir Sigma a KQL")
def convert_sigma_to_kql(yaml_content: str) -> str:
    """Recibe el texto de una regla Sigma (YAML) y la traduce a una consulta KQL para Microsoft Defender."""
    try:
        # Importamos las librerías aquí para evitar errores en el CI
        from sigma.collection import SigmaCollection
        from sigma.backends.kusto import KustoBackend
        from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline
        
        # Cargar la regla
        rules = SigmaCollection.from_yaml(yaml_content)
        
        # Configurar el backend
        backend = KustoBackend(processing_pipeline=microsoft_365_defender_pipeline())
        
        # Convertir
        kql_queries = backend.convert(rules)
        return kql_queries[0]
    except Exception as e:
        return f"Error en la traducción: {e}"