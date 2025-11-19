NAME	:= git.figntigger.io/chrismc/mqtt2rrd
#TAG		:= $$(git log -1 --pretty=%H)
TAG		:= $$(git describe --abbrev=0)
IMG		:= ${NAME}:${TAG}
LATEST	:= ${NAME}:latest

define find.functions
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'
endef

help:
	@echo 'The following commands can be used.'
	@echo ''
	$(call find.functions)

build_edge: ## Build the Docker image for testing - no ":latest" tagged
build_edge:
	$(eval IMG := ${NAME}:edge)
	@echo "building edge"
	# need to adjust the build context
	@docker build -t ${IMG} --file ../docker/Dockerfile ..

push_edge: ## Push the testing Docker image to the package registry
push_edge: build_edge
	$(eval IMG := ${NAME}:edge)
	@echo "pushing \"${IMG}\""
	# push this recent tag
	@docker push ${IMG}

build: ## Build the Docker image
build:
	@echo "building"
	# need to adjust the build context
	@docker build -t ${IMG} --file ../docker/Dockerfile ..
	@echo "tagging"
	@docker tag ${IMG} ${LATEST}

push: ## Push the Docker image to the package registry
push: build
	@echo "pushing \"${IMG}\""
	# push this recent tag
	@docker push ${IMG}
	@echo "pushing \"${NAME}\""
	# push the latest
	@docker push ${NAME}

clean_edge: ## Clean local Docker image for testing
clean_edge:
	@echo "removing Docker image: ${IMG}"
	docker rmi ${IMG} || true

clean: ## Clean local Docker image
clean:
	@echo "removing Docker image: ${IMG} and ${LATEST}"
	docker rmi ${IMG} || true
	docker rmi ${LATEST} || true

.PHONY: help build_edge push_edge build push

# END OF FILE
