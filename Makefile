up:
	sudo docker compose up -d

down:
	sudo docker compose kill
	sudo docker compose rm -f

logs:
	sudo docker compose logs -f
