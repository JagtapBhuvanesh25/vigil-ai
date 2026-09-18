# AppArmor profile — Tier 4 (BLACK)
# Full deny — no file access, no network, no capabilities.
# Container is frozen/killed. Human escalation required.
profile vigil_tier4 flags=(attach_disconnected) {
  # DENY everything
  deny /** rwklx,
  deny network,
  deny capability,
}
