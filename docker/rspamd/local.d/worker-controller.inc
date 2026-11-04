# Password for the controller's write endpoints. The mailbox service needs it
# to teach the classifier from mail people move in and out of Junk.
#
# Rspamd reads RSPAMD_CONTROLLER_PASSWORD from its environment
# (scripts/dev-secrets.sh generates it). If it's unset, learning stays closed:
# Rspamd answers 401 rather than accepting an empty password.
enable_password = "{= env.CONTROLLER_PASSWORD =}";
