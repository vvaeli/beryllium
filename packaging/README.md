# Packaging

Service definitions used by native packages (ROADMAP phase 10). For manual
installs, `sudo berylliumd install` generates an equivalent definition via
kardianos/service; these files are the reference for packages.

- `linux/berylliumd.service` → `/usr/lib/systemd/system/`
- `linux/beryllium.sysusers` → `/usr/lib/sysusers.d/beryllium.conf`
- `macos/io.github.vvaeli.beryllium.plist` → `/Library/LaunchDaemons/`
- Windows: the service is registered by `berylliumd install` (NSIS installer
  calls it), with restart-on-failure recovery.
