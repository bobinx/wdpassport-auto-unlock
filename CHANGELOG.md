# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-07

### Added
* Direct SCSI pass-through using Linux `SG_IO` ioctls in Python's standard library.
* Automatic My Passport drive discovery through Linux sysfs and disk identifiers.
* Unified CLI with `unlock`, `status`, and `unmount` commands.
* Structured JSON output via `--json` for scripts and monitoring.
* Configuration file support (`/etc/wdpassport.conf`) with CLI and environment variable overrides.
* Standard Unix exit codes (0 for success, 1 for runtime failure, 2 for argument or syntax error).
* Oneshot systemd service, boot timer, and udev hotplug rule for automated mounting.
* Offline test suite and Makefile for installation, linting, and testing.

[1.0.0]: https://github.com/bobinx/wdpassport-auto-unlock/releases/tag/v1.0.0
