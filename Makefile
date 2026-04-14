SHELL         := /bin/bash
.SHELLFLAGS   := -eo pipefail -c
.ONESHELL:

include makesupport/env.mk
include makesupport/build.mk
include makesupport/deploy.mk
include makesupport/server.mk
include makesupport/pack.mk
include makesupport/tag.mk

.DEFAULT_GOAL := help

.PHONY: help
help:
	@printf "Usage: make <target>\n\
	\nBuild\
	\n  prep-linux        Build Linux client and copy to DEST_DIR\
	\n  prep-win          Build Windows client and copy to DEST_DIR\
	\n  prep-mac          Build macOS client and copy to DEST_DIR\
	\n  prep-cli          Build all clients and copy to DEST_DIR\
	\n\
	\nDeploy / run\
	\n  deploy-server     Build server and deploy to $(SERVER_NAME) via rsync+ssh\
	\n  deploy-cli        Build + run Linux client (interactive mode)\
	\n  deploy-cli-cmdln  Build + run Linux client with config/resolvers flags\
	\n\
	\nRelease\
	\n  pack              Build all clients and create zip packages in DEST_DIR\
	\n  autotag           Tag + branch HEAD with date/version, push to origin\
	\n\
	\nEnvironment (makesupport/env.mk)\
	\n  SERVER_EXEC_VER   = $(SERVER_EXEC_VER)\
	\n  DEST_DIR          = $(DEST_DIR)\
	\n"
