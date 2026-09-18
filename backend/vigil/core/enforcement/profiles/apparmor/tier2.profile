# AppArmor profile — Tier 2 (ORANGE)
# Read-only filesystem. No network egress. No writes.
profile vigil_tier2 flags=(attach_disconnected) {
  # Read-only file access
  file r,
  # DENY all writes
  deny /** w,
  deny /** a,
  # DENY network
  deny network,
  # Minimal capabilities
  deny capability,
}
