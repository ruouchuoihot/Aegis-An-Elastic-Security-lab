# API Payloads

These JSON files are reference request bodies for manual Kibana, Elasticsearch, and Fleet API calls.

They are kept out of the project root because the core runtime is `docker-compose.yml`, `Makefile`, `scripts/`, and `rules/`.

## Files

- `data_view.json`: Kibana data view for Aegis simulation logs.
- `kibana_security_settings.json`: broad Security App default index/data view settings.
- `force_security_settings.json`: minimal Security App settings for `logs-*` and simulation logs.
- `reset_security_settings.json`: reset payload for Security App default indices.
- `dv_security_settings.json`: older data-view-ID based Security App setting.
- `monitoring_settings.json`: Elasticsearch monitoring collection setting.
- `output_config.json`: Fleet default Elasticsearch output.
- `policy.json`, `policy_fs.json`, `policy_agent.json`: Fleet policy payloads.
