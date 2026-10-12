# Packaging

Service definitions used by native packages (ROADMAP phase 10). For manual
installs, `sudo berylliumd install` generates an equivalent definition via
kardianos/service; these files are the reference for packages.

Linux packages must work with any init system and any desktop/compositor
(GNOME, KDE, Hyprland, niri, sway, ...): the daemon has no systemd
dependency, and each init system gets its own service file.

- `linux/berylliumd.service` → `/usr/lib/systemd/system/` (systemd)
- `linux/openrc/berylliumd` → `/etc/init.d/` (OpenRC)
- `linux/runit/run` → `/etc/runit/sv/berylliumd/run` (Artix) or `/etc/sv/berylliumd/run` (Void)
- `linux/dinit/berylliumd` → `/etc/dinit.d/`
- `linux/s6/berylliumd/` → `/etc/s6/sv/berylliumd/` (s6-rc)
- `linux/beryllium.sysusers` → `/usr/lib/sysusers.d/beryllium.conf`. Systems
  without a sysusers implementation create the group in the install script
  (`groupadd -r beryllium`)

On Artix the init-specific files ship as separate packages
(`beryllium-openrc`, `beryllium-runit`, `beryllium-dinit`, `beryllium-s6`), as
Artix does for its own services. `sudo berylliumd install` detects the init
system by PID 1 and handles runit, dinit and s6 itself.
- `macos/io.github.vvaeli.beryllium.plist` → `/Library/LaunchDaemons/`
- Windows: the service is registered by `berylliumd install` (NSIS installer
  calls it), with restart-on-failure recovery.
