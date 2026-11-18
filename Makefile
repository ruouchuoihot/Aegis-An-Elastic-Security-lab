-include .env

DC=docker compose

.PHONY: setup up down stop clean ps logs-es logs-kibana

setup:
	@if [ ! -f .env ]; then cp .env.example .env; fi
	@echo "Checking system requirements..."
	@if [ "$$(uname -s)" = "Linux" ]; then \
		MAX_MAP_COUNT=$$(sysctl -n vm.max_map_count); \
		if [ $$MAX_MAP_COUNT -lt 262144 ]; then \
			echo "WARNING: vm.max_map_count is too low ($$MAX_MAP_COUNT). Elasticsearch may fail."; \
			echo "Run 'sudo sysctl -w vm.max_map_count=262144' to fix."; \
		fi \
	fi
	@echo "Environment file prepared. Please edit .env if needed."

up: setup
	$(DC) up -d

down:
	$(DC) down

stop:
	$(DC) stop

ps:
	$(DC) ps

logs-es:
	$(DC) logs -f es01

logs-kibana:
	$(DC) logs -f kibana

simulate:
	$(DC) up -d simulator
	@echo "Simulation started. Logs are being sent to logs-aegis-simulation-default"

ai:
	$(DC) up -d --build ai-gateway
	@echo "AI Gateway started on http://localhost:8000"
	@echo "Check http://localhost:8000/docs for the API schema."

advanced:
	$(DC) up -d qdrant spark-master spark-worker
	@echo "Advanced Analytics Layer started."
	@echo "Qdrant: http://localhost:6333"
	@echo "Spark Master: http://localhost:8080"

clean:
	$(DC) down -v --remove-orphans
	@echo "Volumes removed."

test:
	python -m unittest discover -s tests -v

windows-up:
	$(DC) up -d es01
	python scripts/prepare_windows_lab.py --start --run-smoke

kibana:
	$(DC) up -d kibana
	python scripts/setup_kibana_views.py

windows-status:
	docker logs --tail 15 project-aegis-windows-lab-1
	python scripts/verify_windows_lab.py

windows-stop:
	$(DC) --env-file .env --env-file lab/runtime/windows.env -f docker-compose.yml -f compose.windows.yml stop windows-lab
