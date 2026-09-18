# AppArmor profile — Tier 0 (GREEN)
# Default profile: allow everything. Used when risk is minimal.
profile vigil_tier0 flags=(attach_disconnected) {
  # Allow all file reads and writes
  file,
  # Allow network access
  network,
  # Allow capabilities
  capability,
}
