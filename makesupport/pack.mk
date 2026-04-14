# ---------------------------------------------------------------------------
# Packaging target  (converted from: pack)
# ---------------------------------------------------------------------------

.PHONY: pack

pack: prep-linux prep-win prep-mac
	@cd "$(DEST_DIR)"
	shopt -s nocaseglob
	COMMON_FILES=(*resolvers*.txt *client_config*.toml)

	build_zip() {
	  local name="$$1"; shift
	  echo "→ Packaging $$name"
	  zip -r "$$name" "$$@" "$${COMMON_FILES[@]}"
	}

	build_zip "MasterDnsVPN_Client_Linux_$(SERVER_EXEC_VER)" \
	          "MasterDnsVPN_Client_Linux_$(SERVER_EXEC_VER)"

	build_zip "MasterDnsVPN_Client_Win64_$(SERVER_EXEC_VER)" \
	          "MasterDnsVPN_Client_Win64_$(SERVER_EXEC_VER).exe"

	build_zip "MasterDnsVPN_Client_Darwin_$(SERVER_EXEC_VER)" \
	          "MasterDnsVPN_Client_Darwin_$(SERVER_EXEC_VER)"

	echo "Success"
