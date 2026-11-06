# Contributing

Keep changes focused. This tool does one thing well: it unlocks and mounts Western Digital My Passport drives on Linux without external dependencies.

## Development setup

You need Python 3.10 or newer. Everything runs on standard library modules. You do not need virtual environments or third-party packages.

Clone the repository:
```bash
git clone https://github.com/bobinx/wdpassport-auto-unlock.git
cd wdpassport-auto-unlock
```

## Running tests

Run the test suite:
```bash
make test
```

Run syntax checks:
```bash
make lint
```

## Guidelines

- Keep dependencies at zero. Do not add pip packages or compiled C extensions. All SCSI calls and sysfs reads belong in Python's standard library.
- Keep tests fast and offline. Every feature and bug fix needs tests that execute in milliseconds without real hardware or network calls.
- Use standard Unix exit codes. Return 0 on success, 1 on runtime failures, and 2 on argument or configuration errors.
- Open a topic branch for pull requests, keep commits focused, and confirm `make test` and `make lint` pass before submitting.
