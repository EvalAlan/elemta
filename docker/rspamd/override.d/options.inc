# Fail DNS lookups fast rather than holding a message while they time out.
#
# Any lookup that does survive the module overrides should not be able to add
# seconds to a delivery: a slow answer here becomes latency on the SMTP session,
# which is what made this stack's response times so variable.
dns {
  timeout = 1s;
  retransmits = 1;
}
