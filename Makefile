.PHONY: install dev lint test test-unit test-integration format typecheck docker-up docker-down clean

install:
	pip install -e .

dev:
	pip install -e ".[dev,blackfyre]"

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

typecheck:
	mypy src/revgraph/

test:
	pytest tests/ -v

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v -m integration

docker-up:
	docker compose up neo4j -d

docker-down:
	docker compose down

clean:
	rm -rf dist/ build/ *.egg-info .mypy_cache .ruff_cache .pytest_cache htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
