# AppArmor profile — Tier 1 (YELLOW)
# No network egress. File access allowed (read + write).
profile vigil_tier1 flags=(attach_disconnected) {
  # Allow all file reads and writes
  file,
  # DENY outbound network connections
  deny network inet stream,
  deny network inet dgram,
  deny network inet6 stream,
  deny network inet6 dgram,
  # Allow capabilities (except net_admin)
  capability,
  deny capability net_admin,
  deny capability net_raw,
}
