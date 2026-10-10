.DEFAULT_GOAL := all

.PHONY: all install test lint fmt clean

all: install lint test

install:
	pip install -e ".[dev]"

test:
	pytest --tb=short -v

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

fmt:
	ruff format src/ tests/

clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info __pycache__ .pytest_cache

smoke:
	pii-scan detect --source testdata/dirty/ssn.csv --report-format table
	pii-scan detect --source testdata/clean/index.html --report-format json
