DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=operator

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
TAG?=test

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)

docker-build:
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) . --load

docker-push: docker-build
	docker push $(IMAGE):$(TAG)

kind-push: docker-build
	kind load docker-image $(IMAGE):$(TAG)
