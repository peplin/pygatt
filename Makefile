# Makefile for pygatt Python Module.
#
# Source:: https://github.com/ampledata/pygatt
# Author:: Greg Albrecht <gba@orionlabs.co>
# Copyright:: Copyright 2015 Orion Labs, Inc.
# License:: Apache License, Version 2.0
#


.DEFAULT_GOAL := all


all: install_requirements develop

develop:
	python setup.py develop

install_requirements:
	pip install -r requirements.txt

install:
	python setup.py install

uninstall:
	pip uninstall -y pygatt

clean:
	@rm -rf *.egg* build dist *.py[oc] */*.py[co] cover doctest_pypi.cfg \
		nosetests.xml pylint.log output.xml flake8.log tests.log \
		test-result.xml htmlcov fab.log .coverage

publish:
	python setup.py register sdist upload

test:
	tox
