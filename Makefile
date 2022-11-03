up:
	docker compose up -d

down:
	docker compose kill
	docker compose rm -f

logs:
	docker compose logs -f

shell:
	docker compose run --rm app sh

docker-compose.build:
	docker compose build --no-cache
