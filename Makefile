# SCHUBERTH Bluetooth Device Manager (Linux) — dev convenience targets
# Usage: make <target>   (VENV defaults to the durable user-level env)
VENV  ?= $(HOME)/.venvs/schuberth
BIN   := $(VENV)/bin
PY    := $(BIN)/python3

.PHONY: venv install test selftest ui demo detect regression udev

venv:
	python3 -m venv $(VENV)
	$(BIN)/pip install -e .[dev]

install: venv

test:
	$(PY) -m pytest tests/ -q

selftest:
	$(BIN)/schuberth-dfu selftest

ui:
	$(BIN)/schuberth-dfu ui

# UI against simulated devices (no hardware): http://127.0.0.1:8791/
demo:
	$(PY) tools/ui_demo.py

detect:
	$(BIN)/schuberth-dfu detect

# Full re-flash of the connected device with the known-good SC2V2 image.
# Requires the headset plugged in; takes ~5 minutes.
regression:
	$(BIN)/schuberth-dfu update --image firmware/sc2v2-2.4.0.0.img --yes --force

# Install the udev rule (once per machine; then no root is needed).
udev:
	sudo install -m 0644 udev/99-schuberth-dfu.rules /etc/udev/rules.d/
	sudo udevadm control --reload && sudo udevadm trigger --subsystem-match=usb
