# ---------------------------------------------------------------------------
# Environment / version settings  (converted from: ver)
# ---------------------------------------------------------------------------

# Server / service identity
SERVER_NAME                  := sewr4
SERVICE_NAME                 := masterdnsvpn5
SERVICE_DIR                  := /opt/masterdnsvpn5
SERVICE_BIN                  := mdvserver5
SERVER_SERVICE_FRIENDLY_NAME := Server 405

# Release version strings
SERVER_EXEC_VER              := Farvardin25
SERVER_EXEC_VER_FRIENDLY     := Farvardin 25

# Client distribution path
DEST_DIR               := /mnt/c/Projects/denerastin/spr2x/MasterDnsVPN_Client
DEFAULT_RESOLVERS_FILE := Resolvers_(not_for_inside_iran).txt
CLI_CONFIG_DEPLOYED    := 01. $(SERVER_EXEC_VER_FRIENDLY), $(SERVER_SERVICE_FRIENDLY_NAME), client_config
