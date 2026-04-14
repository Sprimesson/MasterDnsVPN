# ---------------------------------------------------------------------------
# Deploy / run targets  (converted from: deploy_cli, deploy_cli_cmdln)
# ---------------------------------------------------------------------------

.PHONY: deploy-cli deploy-cli-cmdln

# Build Linux client, then run it (GUI / interactive mode)
deploy-cli: prep-linux
	@pkill -xi '*masterdnsvpn*' -9 || true
	echo "Running linux cli..."
	cd "$(DEST_DIR)"
	./MasterDnsVPN_Client_Linux_$(SERVER_EXEC_VER)

# Build Linux client, then run it with explicit config / resolvers flags
deploy-cli-cmdln: prep-linux
	@pkill -xi '*masterdnsvpn*' -9 || true
	echo "Running linux cli (cmdln)..."
	cd "$(DEST_DIR)"
	./MasterDnsVPN_Client_Linux_$(SERVER_EXEC_VER) \
		-config    "./$(CLI_CONFIG_DEPLOYED).toml" \
		-resolvers "./$(DEFAULT_RESOLVERS_FILE)"
