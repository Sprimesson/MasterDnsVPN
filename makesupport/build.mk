# ---------------------------------------------------------------------------
# Build targets  (converted from: prep_cli_linux, prep_cli_winmac)
# ---------------------------------------------------------------------------

.PHONY: prep-linux prep-win prep-mac prep-client-config-dest prep-cli

prep-client-config-dest:
	@echo "Copying client config..."
	rm -f "$(DEST_DIR)/01."*"client_config"*".toml"
	cp ./client_config.toml "$(DEST_DIR)/$(CLI_CONFIG_DEPLOYED).toml"

prep-linux: prep-client-config-dest
	@echo "Building client (Linux)..."
	rm -f ./client
	go build ./cmd/client
	echo "Copying client..."
	cp ./client             "$(DEST_DIR)/MasterDnsVPN_Client_Linux_$(SERVER_EXEC_VER)"

prep-win: prep-client-config-dest
	@echo "Building client (Windows)..."
	rm -f ./client.exe
	GOOS=windows GOARCH=amd64 go build ./cmd/client
	echo "Copying client..."
	cp ./client.exe         "$(DEST_DIR)/MasterDnsVPN_Client_Win64_$(SERVER_EXEC_VER).exe"

prep-mac: prep-client-config-dest
	@echo "Building client (macOS)..."
	rm -f ./client-darwin
	GOOS=darwin GOARCH=amd64 go build -o client-darwin ./cmd/client
	echo "Copying client..."
	cp ./client-darwin      "$(DEST_DIR)/MasterDnsVPN_Client_Darwin_$(SERVER_EXEC_VER)"

prep-cli: prep-linux prep-win prep-mac
