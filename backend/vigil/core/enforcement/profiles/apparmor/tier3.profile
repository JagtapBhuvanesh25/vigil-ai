# AppArmor profile — Tier 3 (RED)
# Read-only introspection only. Highly restricted.
profile vigil_tier3 flags=(attach_disconnected) {
  # Allow only reading /proc/self and basic sys info
  /proc/self/** r,
  /sys/fs/cgroup/** r,
  # DENY all other file access
  deny /etc/** rwklx,
  deny /home/** rwklx,
  deny /tmp/** rwklx,
  deny /var/** rwklx,
  # DENY network completely
  deny network,
  # DENY all capabilities
  deny capability,
}
