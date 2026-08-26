.PHONY: help venv install migrate makemigrations run worker beat test lint format \
        up down logs shell dbshell superuser

help:
	@echo "IP Scout - common commands"
	@echo "  make install        Install development requirements"
	@echo "  make migrate        Apply database migrations"
	@echo "  make makemigrations Generate new migrations"
	@echo "  make run            Run the dev server"
	@echo "  make worker         Run a Celery worker (all queues)"
	@echo "  make beat           Run Celery beat"
	@echo "  make test           Run the test suite"
	@echo "  make lint           Run ruff + mypy"
	@echo "  make up             docker compose up -d"
	@echo "  make down           docker compose down"
	@echo "  make logs           docker compose logs -f"

install:
	pip install -r requirements/development.txt

migrate:
	python manage.py migrate

makemigrations:
	python manage.py makemigrations

run:
	python manage.py runserver

worker:
	celery -A config worker -Q logs,ips,whois,iran,maintenance -l info

beat:
	celery -A config beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler

test:
	pytest

lint:
	ruff check .
	mypy .

format:
	ruff format .

superuser:
	python manage.py createsuperuser

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

shell:
	python manage.py shell

dbshell:
	python manage.py dbshell
