.PHONY: sd-webui build install test typecheck package clean

build:
	poetry install


install:
	cp misc/sd-server.service /usr/lib/systemd/user/sd-server.service

test:
	@# Note that extensive integration tests are also run in the bundle repo,
	@# for both sd-server and sd-server-rust, but without code coverage.
	python -c 'import sd_server'
	python -m pytest tests/test_server.py

typecheck:
	python -m mypy sd_server tests --ignore-missing-imports

package:
	python -m sd_server.__about__
	pyinstaller sd-server.spec --clean --noconfirm

PYFILES=$(shell find . -name '*.py')

lint:
	ruff check .

lint-fix:
	poetry run pyupgrade --py38-plus --exit-zero-even-if-changed $(PYFILES)
	ruff check --fix .

format:
	black .

clean:
	rm -rf build dist
	rm -rf sd_server/__pycache__
	pip3 uninstall -y sd_server
