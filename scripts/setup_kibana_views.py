"""Create explicit lab data views without replacing the user's default view."""
from pathlib import Path
import sys
import time

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.prepare_windows_lab import read_env


def main():
    values = read_env()
    url = f"http://localhost:{values.get('KIBANA_PORT', '5601')}"
    with httpx.Client(base_url=url, auth=("elastic", values["ELASTIC_PASSWORD"]),
                      headers={"kbn-xsrf": "aegis-setup"}, timeout=15) as client:
        for _ in range(60):
            try:
                status = client.get("/api/status")
                if status.status_code == 200 and status.json().get("status", {}).get("overall", {}).get("level") == "available":
                    break
            except httpx.HTTPError:
                pass
            time.sleep(2)
        else:
            raise RuntimeError("Kibana is not available yet; check docker compose logs kibana")
        for identifier, title, name in [
            ("aegis-windows-lab", "logs-aegis.windows-*", "Aegis Windows Lab - Actual Endpoint Logs"),
            ("aegis-managed-alerts", "aegis-alerts-*", "Aegis Managed Alerts"),
        ]:
            existing = client.get(f"/api/data_views/data_view/{identifier}")
            if existing.status_code == 404:
                result = client.post("/api/data_views/data_view", json={"data_view": {
                    "id": identifier, "title": title, "name": name, "timeFieldName": "@timestamp", "allowNoIndex": True}})
                result.raise_for_status()
            else:
                existing.raise_for_status()
            check = client.get(f"/api/data_views/data_view/{identifier}")
            check.raise_for_status()
            if check.json()["data_view"]["title"] != title:
                raise RuntimeError(f"Existing data view {identifier} has a different pattern; left unchanged")
            print(f"Ready: {name} ({title})")
    print(f"Kibana: {url}/app/discover")


if __name__ == "__main__":
    main()
