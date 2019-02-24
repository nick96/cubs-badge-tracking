#!/usr/bin/env bash

pipenv run pip freeze >requirements.txt

docker-compose build --force-rm
