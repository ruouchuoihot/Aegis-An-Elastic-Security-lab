"""Install Windows detection normalization/mappings without changing guest credentials."""
import ssl
import httpx
try:
    from .prepare_windows_lab import read_env, RUNTIME, INDEX, PIPELINE, pipeline, detection_mappings
except ImportError:
    from prepare_windows_lab import read_env, RUNTIME, INDEX, PIPELINE, pipeline, detection_mappings


def main():
    values = read_env()
    with httpx.Client(base_url='https://localhost:'+values['ES_PORT'],auth=('elastic',values['ELASTIC_PASSWORD']),
                      verify=ssl.create_default_context(cafile=str(RUNTIME/'oem/ca.crt')),timeout=30) as client:
        for path, body in [(f'/{INDEX}/_mapping', {'properties':{'aegis':{'properties':detection_mappings()}}}),
                           (f'/_ingest/pipeline/{PIPELINE}', pipeline())]:
            response = client.put(path,json=body)
            if response.is_error:
                raise RuntimeError(f'Pack setup failed: {path}, HTTP {response.status_code}: {response.text[:1500]}')
        print('Windows detection mappings and normalization pipeline installed.')


if __name__=='__main__':
    main()
