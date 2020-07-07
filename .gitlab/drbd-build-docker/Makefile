DOCKER_IMAGE_NAME ?= drbd-build

ifneq ($(LINBIT_DOCKER_REGISTRY),)
	DOCKER_IMAGE_NAME := $(LINBIT_DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME)
endif

all:
	docker build -t $(DOCKER_IMAGE_NAME) .

deploy:
	docker push $(DOCKER_IMAGE_NAME)
