# NetMind lab lifecycle. Run from the repository root.
#   make up      build images, create bridges, deploy the lab, build registry.json
#   make down    destroy the lab
#   make test    run unit tests      make lint   run ruff
SHELL := /bin/bash
TOPO_DIR := topology
TOPO := netmind-large.clab.yml
# Use the project venv automatically when it exists, so "make up" works even if it is not activated.
PYTHON ?= $(if $(wildcard $(CURDIR)/.venv/bin/python),$(CURDIR)/.venv/bin/python,python3)

.PHONY: help up down lab-build lab-bridges lab-up run test lint

help:
	@echo "make up | down | lab-build | lab-bridges | lab-up | run | test | lint"

# Build the custom firewall and camera images.
lab-build:
	docker build -t netmind-firewall:latest docker/firewall/
	docker build -t netmind-camera:latest docker/camera/

# Generate the topology and idempotently create host bridges + FORWARD rules
# (safe to run repeatedly; survives reboots because you simply re-run it).
lab-bridges:
	cd $(TOPO_DIR) && $(PYTHON) generate_topology.py --create-bridges

# Deploy the lab and (re)build topology/registry.json from the live containers.
lab-up: lab-bridges
	cd $(TOPO_DIR) && sudo containerlab deploy -t $(TOPO) --reconfigure
	cd $(TOPO_DIR) && $(PYTHON) build_registry.py

up: lab-build lab-up
	@echo "Lab is up. Start the app with: make run"

down:
	cd $(TOPO_DIR) && sudo containerlab destroy -t $(TOPO) --cleanup

run:
	cd agent && uvicorn web_server:app --reload

test:
	$(PYTHON) -m pytest

lint:
	ruff check .
