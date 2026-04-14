# ---------------------------------------------------------------------------
# Server build + deploy target  (converted from: deploy)
# ---------------------------------------------------------------------------

.PHONY: deploy-server

deploy-server:
	@echo "Building server..."
	rm -f ./server
	go build ./cmd/server
	echo "Deploy..."
	rm -f ./$(SERVICE_BIN)
	ln -s ./server ./$(SERVICE_BIN)
	ssh -T $(SERVER_NAME) "echo 'MDV Server: Stopping $(SERVICE_NAME)'; systemctl stop $(SERVICE_NAME)"
	echo "Copying server and config to $(SERVICE_DIR)..."
	rsync -avzL --progress ./$(SERVICE_BIN) ./server_config.toml $(SERVER_NAME):$(SERVICE_DIR)/
	ssh -T $(SERVER_NAME) "echo 'MDV Server: Starting $(SERVICE_NAME)'; systemctl restart $(SERVICE_NAME); journalctl -fu $(SERVICE_NAME)"
