#!/bin/bash
set -e

python -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pytest flake8 flake8-pyproject black bandit build
pip install -e .

black --check .
flake8 .
bandit -r pyscan/
pytest
python -m build