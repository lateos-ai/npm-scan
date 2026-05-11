.PHONY: docker-build docker-push docker-up docker-down docker-test docker-clean docker-login

REGISTRY=ghcr.io/lateos/npm-scan
CLI_TAG=$(REGISTRY):cli
LOCAL_TAG=npm-scan:local

docker-build:
	docker build -f docker/Dockerfile.cli -t $(LOCAL_TAG) .
	docker buildx build --platform linux/amd64,linux/arm64 -t $(CLI_TAG) .

docker-push:
	docker push $(CLI_TAG)

docker-up-cli:
	docker compose -f docker/docker-compose.yml --profile cli up -d cli

docker-up-pipeline:
	docker compose -f docker/docker-compose.yml --profile pipeline up -d

docker-down:
	docker compose -f docker/docker-compose.yml down

docker-test:
	bash docker/test.sh

docker-clean:
	docker compose -f docker/docker-compose.yml down -v
	docker rmi $(LOCAL_TAG) || true

docker-login:
	echo "Login to GHCR:"
	@echo "  echo $$GITHUB_TOKEN | docker login ghcr.io -u $$GITHUB_USERNAME --password-stdin"
