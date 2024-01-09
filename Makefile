default: update requirements

update:
	poetry update

requirements:
	poetry export -f requirements.txt --output requirements.txt --without-hashes

.PHONY: requirements