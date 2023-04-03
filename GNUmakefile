# If you see pwd_unknown showing up, this is why. Re-calibrate your system.
PWD ?= pwd_unknown

TIME									:= $(shell date +%s)
export TIME
# PROJECT_NAME defaults to name of the current directory.
# should not to be changed if you follow GitOps operating procedures.
PROJECT_NAME = docker_shell#$(notdir $(PWD))

# Note. If you change this, you also need to update docker-compose.yml.
# only useful in a setting with multiple services/ makefiles.
ifneq ($(target),)
SERVICE_TARGET := $(target)
else
SERVICE_TARGET := btcdeb
endif
export SERVICE_TARGET

ifeq ($(user),root)
HOST_USER := root
HOST_UID  := $(strip $(if $(uid),$(uid),0))
else
# allow override by adding user= and/ or uid=  (lowercase!).
# uid= defaults to 0 if user= set (i.e. root).
# USER retrieved from env, UID from shell.
HOST_USER :=  $(strip $(if $(USER),$(USER),nodummy))
HOST_UID  :=  $(strip $(if $(shell id -u),$(shell id -u),4000))
endif
ifneq ($(uid),)
HOST_UID  := $(uid)
endif

ifeq ($(ssh-pkey),)
SSH_PRIVATE_KEY := $(HOME)/.ssh/id_rsa
else
SSH_PRIVATE_KEY := $(ssh-pkey)
endif
export SSH_PRIVATE_KEY

ifeq ($(alpine),)
ALPINE_VERSION := 3.15
else
ALPINE_VERSION := $(alpine)
endif
export ALPINE_VERSION

ifeq ($(nocache),true)
NO_CACHE := --no-cache
else
NO_CACHE :=
endif
export NO_CACHE

ifeq ($(verbose),true)
VERBOSE := --verbose
else
VERBOSE :=
endif
export VERBOSE

ifneq ($(passwd),)
PASSWORD := $(passwd)
else
PASSWORD := changeme
endif
export PASSWORD


THIS_FILE := $(lastword $(MAKEFILE_LIST))

ifeq ($(cmd),)
CMD_ARGUMENTS :=
else
CMD_ARGUMENTS := $(cmd)
endif
export CMD_ARGUMENTS

# export such that its passed to shell functions for Docker to pick up.
export PROJECT_NAME
export HOST_USER
export HOST_UID

DOCKER:=$(shell which docker)
export DOCKER
DOCKER_COMPOSE:=$(shell which docker-compose)
export DOCKER_COMPOSE

# all our targets are phony (no files to check).
.PHONY: debian build-debian rebuild-debian alpine shell help alpine-build alpine-rebuild build rebuild alpine-test service login  clean

# suppress makes own output
#.SILENT:

# Regular Makefile part for buildpypi itself
default:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?##/ {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
help:## 	print verbose help
	@echo ''
	@echo ''
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':	' |  sed -e 's/^/ /' ## verbose help ideas
	@sed -n 's/^## 	//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

.PHONY: report
report:## 	print make args
	@echo ''
	@echo 'PWD=${PWD}'
	@echo 'DOCKER=${DOCKER}'
	@echo 'DOCKER_COMPOSE=${DOCKER_COMPOSE}'
	@echo 'THIS_FILE=${THIS_FILE}'
	@echo 'TIME=${TIME}'
	@echo 'HOST_USER=${HOST_USER}'
	@echo 'HOST_UID=${HOST_UID}'
	@echo 'SERVICE_TARGET=${SERVICE_TARGET}'
	@echo 'ALPINE_VERSION=${ALPINE_VERSION}'
	@echo 'DIND_VERSION=${DIND_VERSION}'
	@echo 'DEBIAN_VERSION=${DEBIAN_VERSION}'
	@echo 'PROJECT_NAME=${PROJECT_NAME}'
	@echo 'PASSWORD=${PASSWORD}'
	@echo 'CMD_ARGUMENTS=${CMD_ARGUMENTS}'
	@echo ''

all:## 	docker-compose up
	$(DOCKER_COMPOSE) up

shell:## 	
ifeq ($(CMD_ARGUMENTS),)
	$(DOCKER_COMPOSE) $(VERBOSE) -p $(PROJECT_NAME)_$(HOST_UID) run --rm ${SERVICE_TARGET} bash
else
	$(DOCKER_COMPOSE) $(VERBOSE) -p $(PROJECT_NAME)_$(HOST_UID) run --rm $(SERVICE_TARGET) bash -c "$(CMD_ARGUMENTS)"
endif

build: 	docker-compose build
	# only build the container. Note, docker does this also if you apply other targets.
	$(DOCKER_COMPOSE) build $(NO_CACHE)  $(VERBOSE) ${SERVICE_TARGET}

rebuild: 	docker-compose build --no-cache
	# force a rebuild by passing --no-cache
	$(DOCKER_COMPOSE) build --no-cache $(VERBOSE) ${SERVICE_TARGET}

test-whatami:## 	run whatami in docker container
	$(DOCKER_COMPOSE) -p $(PROJECT_NAME)_$(HOST_UID) run --rm ${SERVICE_TARGET} sh -c '\
		echo "I am `whoami`. My uid is `id -u`." && /bin/bash -c "curl -fsSL https://raw.githubusercontent.com/randymcmillan/docker.shell/master/whatami"' \
	&& echo success

service:## 	
ifeq ($(CMD_ARGUMENTS),)
	$(DOCKER_COMPOSE) -p $(PROJECT_NAME)_$(HOST_UID) up -d ${SERVICE_TARGET}
else
	$(DOCKER_COMPOSE) -p $(PROJECT_NAME)_$(HOST_UID) up -d $(SERVICE_TARGET)
	docker exec -it $(PROJECT_NAME)_$(HOST_UID) bash -c "${CMD_ARGUMENTS}"
endif

login: service
	# run as a service and attach to it
	docker exec -it $(PROJECT_NAME)_$(HOST_UID) sh

.PHONY: docs
docs:## 	
	@echo docs
	@install README.md index.md


link:
	@bash -c '$(pwd) install -v docker-compose.yml ${HOME}/docker-compose.yml && install -v alpine ${HOME}/alpine && install -v GNUmakefile ${HOME}/GNUmakefile && install -v .dockerignore ${HOME}/.dockerignore'

clean:
	# remove created images
	@$(DOCKER_COMPOSE) -p $(PROJECT_NAME)_$(HOST_UID) down --remove-orphans --rmi all 2>/dev/null \
	&& echo 'Image(s) for "$(PROJECT_NAME):$(HOST_USER)" removed.' \
	|| echo 'Image(s) for "$(PROJECT_NAME):$(HOST_USER)" already removed.'
#######################
.PHONY: prune
prune:## 	docker system prune -af (very destructive!)
	$(DOCKER_COMPOSE) -p $(PROJECT_NAME) down
	docker system prune -af &



host-install:## 	install on host
	make -f Makefile install
host-mostlyclean:## 	rm -f *.lo
	make -f Makefile mostlyclean-libtool

-include Makefile
