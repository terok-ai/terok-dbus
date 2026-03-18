.PHONY: all lint format test test-unit ruff-report bandit-report sonar-inputs tach security docstrings complexity deadcode reuse check install install-dev docs docs-build clean spdx

REPORTS_DIR ?= reports
COVERAGE_XML ?= $(REPORTS_DIR)/coverage.xml
UNIT_JUNIT_XML ?= $(REPORTS_DIR)/unit.junit.xml
RUFF_REPORT ?= $(REPORTS_DIR)/ruff-report.json
BANDIT_REPORT ?= $(REPORTS_DIR)/bandit-report.json

all: check

test: test-unit

# Run linter and format checker (fast, run before commits)
lint:
	mkdir -p $(REPORTS_DIR)
	poetry run ruff check --exit-zero --output-format=json --output-file=$(RUFF_REPORT) .
	poetry run ruff check .
	poetry run ruff format --check .

# Auto-fix lint issues and format code
format:
	poetry run ruff check --fix .
	poetry run ruff format .

# Run tests with coverage
test-unit:
	mkdir -p $(REPORTS_DIR)
	poetry run pytest tests/ --cov=terok_dbus --cov-report=term-missing --cov-report=xml:$(COVERAGE_XML) --junitxml=$(UNIT_JUNIT_XML) -o junit_family=legacy
	@echo "NOTE: Target 95%+ test coverage."

# Write Ruff's JSON report without failing on findings.
ruff-report:
	mkdir -p $(REPORTS_DIR)
	poetry run ruff check --exit-zero --output-format=json --output-file=$(RUFF_REPORT) .

# Write Bandit's JSON report without failing on findings.
bandit-report:
	mkdir -p $(REPORTS_DIR)
	poetry run bandit -r src/terok_dbus/ --exit-zero -f json -o $(BANDIT_REPORT)

# Generate the files SonarQube Cloud imports from reports/.
sonar-inputs: test-unit ruff-report bandit-report

# Check module boundary rules (tach.toml)
tach:
	poetry run tach check

# Run SAST security scan
security:
	mkdir -p $(REPORTS_DIR)
	poetry run bandit -r src/terok_dbus/ --exit-zero -f json -o $(BANDIT_REPORT)
	poetry run bandit -r src/terok_dbus/ -ll

# Check docstring coverage (minimum 95%)
docstrings:
	poetry run docstr-coverage src/terok_dbus/ --fail-under=95

# Check cognitive complexity (advisory — lists functions exceeding threshold)
complexity:
	poetry run complexipy src/terok_dbus/ --max-complexity-allowed 15 --failed; true

# Find dead code (cross-file, min 80% confidence)
deadcode:
	poetry run vulture src/terok_dbus/ vulture_whitelist.py --min-confidence 80

# Check REUSE (SPDX license/copyright) compliance
reuse:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	poetry run reuse lint

# Add SPDX header to files.
# NAME must be the real name of the person responsible for creating the file (not a project name).
# Example: make spdx NAME="Jiri Vyskocil" FILES="src/terok_dbus/foo.py"
spdx:
ifndef NAME
	$(error NAME is required — use the real name of the copyright holder, e.g. make spdx NAME="Jiri Vyskocil" FILES="src/terok_dbus/foo.py")
endif
	poetry run reuse annotate --template compact --copyright "$(NAME)" --license Apache-2.0 $(FILES)

# Run all checks (equivalent to CI)
check: lint test-unit tach security docstrings deadcode reuse

# Install runtime dependencies only
install:
	poetry install --only main

# Install all dependencies (dev, test, docs)
install-dev:
	poetry install --with dev,test,docs

# Build documentation locally
docs:
	poetry run mkdocs serve

# Build documentation for deployment
docs-build:
	poetry run mkdocs build --strict

# Clean build artifacts
clean:
	rm -rf dist/ build/ site/ reports/ .coverage .pytest_cache/ .ruff_cache/ .complexipy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
