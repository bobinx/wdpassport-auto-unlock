# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-07

### Added
* Zero-dependency direct SCSI pass-through implementation using Linux `SG_IO` ioctl.
* Automatic Western Digital My Passport drive discovery through Linux sysfs and disk identifiers.
* Unified command line interface with `unlock`, `status`, and `unmount` commands.
* Structured JSON output support via `--json` for scripting and monitoring.
* Secure configuration file support (`/etc/wdpassport.conf`) with CLI and environment variable overrides.
* Standardized Unix exit codes (0 for success, 1 for runtime failure, 2 for configuration or argument error).
* Automated systemd oneshot service, boot timer, and udev hotplug rule.
* Comprehensive offline test suite and POSIX-compliant Makefile for build, lint, install, and uninstall workflows.

[1.0.0]: https://github.com/bobinx/wdpassport-auto-unlock/releases/tag/v1.0.0
