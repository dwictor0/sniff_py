#!/bin/bash
set -e

# Cria venv apenas se não existir
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate

python3 -m pip install --upgrade pip
pip install -r requirements.txt
pip install pytest flake8 flake8-pyproject black bandit build
pip install -e .

black --check .
flake8 .
bandit -r pyscan/
pytest
python3 -m build