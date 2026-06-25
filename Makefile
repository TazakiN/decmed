SHELL := /usr/bin/env bash

PID_DIR := .run
LOG_DIR := $(PID_DIR)/logs

ROOT_DIR := $(CURDIR)
PRE_WORKDIR := proxy-reencryption
COMPOSE_FILE := proxy-reencryption/docker-compose.yaml
PRE_BIN := .cargo-target/release/proxy_reencryption
PRE_ALT_BIN := proxy-reencryption/target/release/proxy_reencryption
HOSPITAL_BIN := .cargo-target/release/client-hospital-tauri
PATIENT_BIN := .cargo-target/release/client-patient-tauri-v2
HOSPITAL_PROFILES := admin dokter perawat lab apoteker
STATUS_TIMEOUT ?= 3
IOTA_URL ?= http://103.107.4.64:9000
GAS_STATION_BASE_URL ?= http://103.107.4.68:9528/v1
IPFS_BASE_URL ?= http://103.107.4.68:5001/api/v0

.PHONY: build build-pre build-clients start stop restart status logs clean-pids

build: build-pre build-clients

build-pre:
	cargo build --release --manifest-path proxy-reencryption/Cargo.toml

build-clients:
	for dir in client/*-tauri*/; do \
		(cd "$$dir" && pnpm install && pnpm tauri build); \
	done

start:
	@mkdir -p "$(PID_DIR)" "$(LOG_DIR)"
	docker compose -f "$(COMPOSE_FILE)" up -d redis
	@if [ -x "$(PRE_BIN)" ]; then \
		pre_bin="$(ROOT_DIR)/$(PRE_BIN)"; \
	elif [ -x "$(PRE_ALT_BIN)" ]; then \
		pre_bin="$(ROOT_DIR)/$(PRE_ALT_BIN)"; \
	else \
		echo "PRE binary not found. Run: make build-pre"; \
		exit 1; \
	fi; \
	if [ -f "$(PID_DIR)/proxy_reencryption.pid" ] && kill -0 "$$(cat "$(PID_DIR)/proxy_reencryption.pid")" 2>/dev/null; then \
		echo "proxy_reencryption already running with PID $$(cat "$(PID_DIR)/proxy_reencryption.pid")"; \
	else \
		cd "$(PRE_WORKDIR)"; \
		nohup "$$pre_bin" >"$(ROOT_DIR)/$(LOG_DIR)/proxy_reencryption.log" 2>&1 & \
		echo $$! >"$(ROOT_DIR)/$(PID_DIR)/proxy_reencryption.pid"; \
		echo "Started proxy_reencryption with PID $$(cat "$(ROOT_DIR)/$(PID_DIR)/proxy_reencryption.pid")"; \
	fi
	@if [ ! -x "$(HOSPITAL_BIN)" ]; then \
		echo "Hospital client binary not found. Run: make build-clients"; \
		exit 1; \
	fi; \
	for profile in $(HOSPITAL_PROFILES); do \
		pid_file="$(PID_DIR)/client-hospital-tauri-$$profile.pid"; \
		log_file="$(LOG_DIR)/client-hospital-tauri-$$profile.log"; \
		if [ -f "$$pid_file" ] && kill -0 "$$(cat "$$pid_file")" 2>/dev/null; then \
			echo "client-hospital-tauri --profile=$$profile already running with PID $$(cat "$$pid_file")"; \
		else \
			nohup "$(HOSPITAL_BIN)" --profile="$$profile" >"$$log_file" 2>&1 & \
			echo $$! >"$$pid_file"; \
			echo "Started client-hospital-tauri --profile=$$profile with PID $$(cat "$$pid_file")"; \
		fi; \
	done
	@if [ ! -x "$(PATIENT_BIN)" ]; then \
		echo "Patient client binary not found. Run: make build-clients"; \
		exit 1; \
	fi; \
	if [ -f "$(PID_DIR)/client-patient-tauri-v2.pid" ] && kill -0 "$$(cat "$(PID_DIR)/client-patient-tauri-v2.pid")" 2>/dev/null; then \
		echo "client-patient-tauri-v2 already running with PID $$(cat "$(PID_DIR)/client-patient-tauri-v2.pid")"; \
	else \
		nohup "$(PATIENT_BIN)" >"$(LOG_DIR)/client-patient-tauri-v2.log" 2>&1 & \
		echo $$! >"$(PID_DIR)/client-patient-tauri-v2.pid"; \
		echo "Started client-patient-tauri-v2 with PID $$(cat "$(PID_DIR)/client-patient-tauri-v2.pid")"; \
	fi

stop:
	@if compgen -G "$(PID_DIR)/*.pid" >/dev/null; then \
		for pid_file in "$(PID_DIR)"/*.pid; do \
			pid="$$(cat "$$pid_file" 2>/dev/null || true)"; \
			name="$$(basename "$$pid_file" .pid)"; \
			if [ -n "$$pid" ] && kill -0 "$$pid" 2>/dev/null; then \
				kill "$$pid" 2>/dev/null || true; \
				echo "Stopped $$name with PID $$pid"; \
			else \
				echo "$$name was not running"; \
			fi; \
			rm -f "$$pid_file"; \
		done; \
	else \
		echo "No PID files found in $(PID_DIR)"; \
	fi
	@pkill -f '[p]roxy-reencryption/target/release/proxy_reencryption' 2>/dev/null || true
	@pkill -f '[.]cargo-target/release/proxy_reencryption' 2>/dev/null || true
	@pkill -f '[.]cargo-target/release/client-hospital-tauri --profile=' 2>/dev/null || true
	@pkill -f '[.]cargo-target/release/client-patient-tauri-v2' 2>/dev/null || true
	docker compose -f "$(COMPOSE_FILE)" stop redis

restart: stop start

status:
	@echo "Redis:"
	@docker compose -f "$(COMPOSE_FILE)" ps redis
	@echo
	@echo "External services:"
	@check_required_tool() { \
		if ! command -v "$$1" >/dev/null 2>&1; then \
			echo "$$2: skipped ($$1 not found)"; \
			return 1; \
		fi; \
	}; \
	check_ipfs() { \
		if ! check_required_tool curl "IPFS"; then return 0; fi; \
		if curl -fsS --max-time "$(STATUS_TIMEOUT)" -X POST "$(IPFS_BASE_URL)/version" >/dev/null 2>&1; then \
			echo "IPFS: reachable ($(IPFS_BASE_URL))"; \
		else \
			echo "IPFS: unreachable ($(IPFS_BASE_URL))"; \
		fi; \
	}; \
	check_iota() { \
		if ! check_required_tool curl "IOTA"; then return 0; fi; \
		response="$$(curl -fsS --max-time "$(STATUS_TIMEOUT)" \
			-H "Content-Type: application/json" \
			-d '{"jsonrpc":"2.0","id":1,"method":"iotax_getReferenceGasPrice","params":[]}' \
			"$(IOTA_URL)" 2>/dev/null)" && \
			printf "%s" "$$response" | grep -q '"result"'; \
		if [ $$? -eq 0 ]; then \
			echo "IOTA: reachable ($(IOTA_URL))"; \
		else \
			echo "IOTA: unreachable or unhealthy ($(IOTA_URL))"; \
		fi; \
	}; \
	check_gas_station() { \
		if ! check_required_tool curl "Gas station"; then return 0; fi; \
		http_code="$$(curl -sS --max-time "$(STATUS_TIMEOUT)" -o /dev/null -w "%{http_code}" "$(GAS_STATION_BASE_URL)" 2>/dev/null || true)"; \
		if [ "$$http_code" != "000" ] && [ -n "$$http_code" ]; then \
			echo "Gas station: responding HTTP $$http_code ($(GAS_STATION_BASE_URL))"; \
		else \
			echo "Gas station: unreachable ($(GAS_STATION_BASE_URL))"; \
		fi; \
	}; \
	check_ipfs; \
	check_iota; \
	check_gas_station
	@echo
	@echo "Local processes:"
	@if compgen -G "$(PID_DIR)/*.pid" >/dev/null; then \
		for pid_file in "$(PID_DIR)"/*.pid; do \
			pid="$$(cat "$$pid_file" 2>/dev/null || true)"; \
			name="$$(basename "$$pid_file" .pid)"; \
			if [ -n "$$pid" ] && kill -0 "$$pid" 2>/dev/null; then \
				echo "$$name: running with PID $$pid"; \
			else \
				echo "$$name: stopped"; \
			fi; \
		done; \
	else \
		echo "No PID files found in $(PID_DIR)"; \
	fi

logs:
	@mkdir -p "$(LOG_DIR)"
	tail -n 80 -f "$(LOG_DIR)"/*.log

clean-pids:
	rm -f "$(PID_DIR)"/*.pid
