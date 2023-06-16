NAME	:= git.figntigger.id.au/chrismc/mqtt2rrd
#TAG		:= $$(git log -1 --pretty=%H)
TAG		:= $$(cd MQTT2RRD ; git describe --abbrev=0)
IMG		:= ${NAME}:${TAG}
LATEST	:= ${NAME}:latest

define find.functions
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'
endef

help:
	@echo 'The following commands can be used.'
	@echo ''
	$(call find.functions)

build: ## Build the Docker image
build:
	@echo "building"
	@docker build -t ${IMG} .
	@echo "tagging"
	@docker tag ${IMG} ${LATEST}

push: ## Push the Docker image to the package registry
push:
	# push this recent tag
	@docker push ${IMG}
	# push the latest
	@docker push ${NAME}

.PHONY: help build push

# END OF FILE
