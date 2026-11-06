# Contributing

Contributions are welcome. Please keep changes aligned with the Unix philosophy: do one thing and do it well, maintain zero external dependencies, and avoid feature bloat.

## Development setup

The tool uses only Python standard library modules. You need Python 3.9 or newer. No virtual environments or third-party packages are required.

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

Run bytecode and syntax checks:
```bash
make lint
```

## Guidelines

* **Zero external dependencies**: Do not introduce pip dependencies or third-party runtime modules. All SCSI commands and sysfs interactions must use the standard library.
* **Fast offline tests**: Any new feature or bug fix must include unit tests that run offline in milliseconds.
* **Standard exit codes**: Return 0 for success, 1 for operational failures, and 2 for argument or configuration errors.
* **Pull requests**: Create a topic branch, keep commits focused, and ensure `make test` and `make lint` pass before opening a pull request.
