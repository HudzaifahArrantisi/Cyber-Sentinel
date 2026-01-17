# ============================================
# CyberNet Sentinel - Makefile
# Quick commands for development & deployment
# ============================================

.PHONY: help install run test docker-build docker-run docker-stop clean

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python
PIP := pip
DOCKER := docker
DOCKER_COMPOSE := docker-compose
IMAGE_NAME := cybernet-sentinel
CONTAINER_NAME := cybernet-sentinel

# ============================================
# Help
# ============================================
help: ## Show this help message
	@echo "CyberNet Sentinel - Available Commands"
	@echo ""
	@echo "Installation:"
	@echo "  make install          - Install dependencies"
	@echo "  make install-dev      - Install dev dependencies"
	@echo "  make setup            - Initial setup"
	@echo ""
	@echo "Running:"
	@echo "  make run              - Run network analyzer"
	@echo ""
	@echo "Testing:"
	@echo "  make test             - Run all tests"
	@echo "  make test-coverage    - Run tests with coverage"
	@echo "  make lint             - Run linters"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build     - Build Docker image"
	@echo "  make docker-run       - Run Docker container"
	@echo "  make docker-stop      - Stop Docker container"
	@echo "  make compose-up       - Start with docker-compose"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean            - Clean temp files"
	@echo "  make clean-all        - Clean everything"

# ============================================
# Installation
# ============================================
install:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

install-dev:
	$(PIP) install -r requirements.txt
	$(PIP) install pytest black flake8 mypy pylint

setup: install
	@if not exist .env copy .env.example .env
	@if not exist reports mkdir reports
	@if not exist logs mkdir logs

# ============================================
# Running
# ============================================
run:
	$(PYTHON) network_analyzer.py

# ============================================
# Testing
# ============================================
test:
	pytest tests/ -v

test-coverage:
	pytest --cov=src --cov-report=html tests/

lint:
	flake8 src/ network_analyzer.py
	pylint src/ network_analyzer.py

format:
	black src/ network_analyzer.py tests/

# ============================================
# Docker
# ============================================
docker-build:
	$(DOCKER) build -t $(IMAGE_NAME):latest .

docker-run:
	$(DOCKER) run -it --rm --network host --privileged --name $(CONTAINER_NAME) -v $(PWD)/reports:/app/reports $(IMAGE_NAME):latest

docker-stop:
	$(DOCKER) stop $(CONTAINER_NAME)
	$(DOCKER) rm $(CONTAINER_NAME)

docker-logs:
	$(DOCKER) logs -f $(CONTAINER_NAME)

docker-clean:
	$(DOCKER) stop $(CONTAINER_NAME) || exit 0
	$(DOCKER) rm $(CONTAINER_NAME) || exit 0
	$(DOCKER) rmi $(IMAGE_NAME):latest || exit 0

# ============================================
# Docker Compose
# ============================================
compose-up:
	$(DOCKER_COMPOSE) up -d

compose-down:
	$(DOCKER_COMPOSE) down

compose-logs:
	$(DOCKER_COMPOSE) logs -f

compose-rebuild:
	$(DOCKER_COMPOSE) build --no-cache
	$(DOCKER_COMPOSE) up -d

# ============================================
# Cleanup
# ============================================
clean:
	@if exist __pycache__ rmdir /s /q __pycache__
	@del /s /q *.pyc *.pyo 2>nul
	@if exist .pytest_cache rmdir /s /q .pytest_cache
	@if exist htmlcov rmdir /s /q htmlcov
	@if exist .mypy_cache rmdir /s /q .mypy_cache

clean-reports:
	@del /q reports\*.json reports\*.html reports\*.csv 2>nul

clean-all: clean clean-reports docker-clean
