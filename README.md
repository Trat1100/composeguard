# ComposeGuard

ComposeGuard is a small command-line audit tool for Docker Compose files. It catches common container configuration risks before a stack is deployed, including privileged containers, host control-socket mounts, plaintext secret-like environment values, broadly published ports, mutable image tags, and missing health checks.

## What it checks

- Privileged mode, host networking, and `cap_add: [ALL]`.
- Docker socket and broad host-directory bind mounts.
- Secret-like environment variables with inline values. Reports identify the variable name but never print its value.
- Ports published beyond loopback.
- Images without a fixed tag or digest.
- Explicit root users and useful hardening gaps such as missing health checks, restart policies, read-only filesystems, and resource limits.

Findings use `critical`, `warning`, and `info` severities. The rules are intentionally static and conservative; they do not execute containers or attempt to resolve environment substitutions.

## Install and run

```shell
python -m venv .venv
# Activate the environment, then:
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
composeguard compose.yaml
```

For automation, request JSON and choose the failure threshold:

```shell
composeguard compose.yaml --format json --fail-on warning
```

Exit codes: `0` means no finding met the selected threshold, `1` means one or more did, and `2` means the input could not be read or parsed.

## Example

```yaml
services:
  web:
    image: example/web:1.2.3
    user: "10001:10001"
    read_only: true
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      DATABASE_PASSWORD: ${DATABASE_PASSWORD:?set DATABASE_PASSWORD}
```

## Development

```shell
python -m pytest -q
```

GitHub Actions runs the test suite on Python 3.11 and 3.12.

## Limitations

- This is a static checker, not a replacement for Docker/Compose validation, image scanning, runtime policy enforcement, or a host firewall review.
- Environment interpolation is treated as external configuration. The tool does not inspect the values supplied by the shell or a `.env` file.
- Compose extensions and custom YAML tags may not be supported.
- No license is included pending the owner's license choice.
