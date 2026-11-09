from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass

import yaml


MAX_FILE_BYTES = 1_000_000
SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}
SECRET_NAME = re.compile(r"(?:^|_)(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|PRIVATE_KEY)(?:_|$)", re.I)
INTERPOLATION = re.compile(r"\$\{[^}]+\}")


class ComposeFileError(ValueError):
    """Raised when a Compose file is invalid or outside the supported shape."""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    location: str
    message: str


@dataclass(frozen=True)
class ScanReport:
    source: str
    findings: tuple[Finding, ...]

    def counts(self) -> dict[str, int]:
        result = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            result[finding.severity] += 1
        return result

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "summary": self.counts(),
            "findings": [asdict(finding) for finding in self.findings],
        }


def _add(
    findings: list[Finding],
    rule_id: str,
    severity: str,
    location: str,
    message: str,
) -> None:
    findings.append(Finding(rule_id, severity, location, message))


def _secret_is_inlined(value: object) -> bool:
    if value is None or isinstance(value, bool):
        return False
    text = str(value).strip()
    return bool(text) and not INTERPOLATION.search(text)


def _environment_items(environment: object) -> list[tuple[str, object]]:
    if isinstance(environment, Mapping):
        return [(str(key), value) for key, value in environment.items()]
    if isinstance(environment, list):
        items: list[tuple[str, object]] = []
        for entry in environment:
            if isinstance(entry, str):
                name, separator, value = entry.partition("=")
                items.append((name, value if separator else None))
        return items
    return []


def _is_root_user(value: object) -> bool:
    if isinstance(value, int):
        return value == 0
    if not isinstance(value, str):
        return False
    return value.strip().lower() in {"0", "root", "0:0", "root:root"}


def _mount_source(mount: object) -> tuple[str | None, str | None]:
    if isinstance(mount, Mapping):
        source = mount.get("source")
        kind = mount.get("type")
        return (str(source) if source is not None else None, str(kind) if kind else None)
    if isinstance(mount, str):
        parts = mount.split(":")
        if len(parts) >= 2:
            return parts[0], "bind" if parts[0].startswith(("/", "\\", ".")) or re.match(r"^[A-Za-z]:[\\/]", parts[0]) else None
    return None, None


def _scan_service(name: str, service: Mapping[str, object], findings: list[Finding]) -> None:
    prefix = f"services.{name}"

    if service.get("privileged") is True:
        _add(findings, "privileged-container", "critical", f"{prefix}.privileged", "Privileged containers receive broad host capabilities; remove privileged mode or document a narrow alternative.")

    if str(service.get("network_mode", "")).lower() == "host":
        _add(findings, "host-network", "critical", f"{prefix}.network_mode", "Host networking bypasses network isolation; use a dedicated Compose network where possible.")

    capabilities = service.get("cap_add", [])
    if isinstance(capabilities, list) and any(str(cap).upper() == "ALL" for cap in capabilities):
        _add(findings, "all-capabilities", "critical", f"{prefix}.cap_add", "Adding every Linux capability grants excessive privilege; add only the capabilities the service needs.")

    image = service.get("image")
    if isinstance(image, str) and image:
        last_part = image.rsplit("/", 1)[-1]
        has_tag = ":" in last_part
        if "@sha256:" in image:
            pass
        elif not has_tag or last_part.endswith(":latest"):
            _add(findings, "mutable-image-tag", "warning", f"{prefix}.image", "Pin the image to a specific version or digest so deployments are reproducible.")
    elif "build" not in service:
        _add(findings, "missing-image-or-build", "warning", prefix, "Declare an image or build context for this service.")

    for key, value in _environment_items(service.get("environment")):
        if SECRET_NAME.search(key) and _secret_is_inlined(value):
            _add(findings, "inline-secret", "critical", f"{prefix}.environment.{key}", "A secret-like environment variable appears to contain an inline value; move it to a secret store or an ignored local environment file.")

    ports = service.get("ports", [])
    if isinstance(ports, list):
        for index, port in enumerate(ports):
            location = f"{prefix}.ports[{index}]"
            if isinstance(port, Mapping):
                host_ip = str(port.get("host_ip", ""))
                if port.get("published") is not None and host_ip not in {"127.0.0.1", "::1"}:
                    _add(findings, "public-port-binding", "warning", location, "This published port is not limited to loopback; bind it to a trusted interface or place it behind a firewall.")
            elif isinstance(port, str) and len(port.split(":")) >= 2:
                parts = port.split(":")
                host_ip = parts[0] if len(parts) >= 3 and ("." in parts[0] or ":" in parts[0]) else ""
                if host_ip not in {"127.0.0.1", "::1"}:
                    _add(findings, "public-port-binding", "warning", location, "This published port is not limited to loopback; bind it to a trusted interface or place it behind a firewall.")

    volumes = service.get("volumes", [])
    if isinstance(volumes, list):
        for index, mount in enumerate(volumes):
            source, kind = _mount_source(mount)
            if kind == "bind" and source:
                normalized = source.replace("\\", "/").lower()
                if normalized in {"/var/run/docker.sock", "/", "/etc", "/root", "/home"}:
                    _add(findings, "sensitive-host-mount", "critical", f"{prefix}.volumes[{index}]", "This mount exposes a sensitive host path to the container; avoid mounting host control sockets or broad system directories.")

    if _is_root_user(service.get("user")):
        _add(findings, "root-container-user", "warning", f"{prefix}.user", "The container is explicitly configured to run as root; use a dedicated unprivileged user if the image supports it.")
    elif not service.get("user"):
        _add(findings, "user-not-pinned", "info", f"{prefix}.user", "No container user is declared; verify the image's default user and prefer an unprivileged account.")

    healthcheck = service.get("healthcheck")
    if not isinstance(healthcheck, Mapping) or healthcheck.get("disable") is True:
        _add(findings, "healthcheck-missing", "warning", f"{prefix}.healthcheck", "Add a health check so an orchestrator can distinguish a running process from a ready service.")

    if not service.get("restart"):
        _add(findings, "restart-policy-missing", "info", f"{prefix}.restart", "Choose an explicit restart policy for services that should recover after a host reboot.")

    if service.get("read_only") is not True:
        _add(findings, "root-filesystem-writable", "info", f"{prefix}.read_only", "Consider a read-only container filesystem and explicit writable volumes where practical.")

    deploy = service.get("deploy")
    resources = deploy.get("resources") if isinstance(deploy, Mapping) else None
    limits = resources.get("limits") if isinstance(resources, Mapping) else None
    if not isinstance(limits, Mapping) or not limits:
        _add(findings, "resource-limits-missing", "info", f"{prefix}.deploy.resources.limits", "Consider CPU and memory limits to reduce noisy-neighbor risk on shared hosts.")


def scan_text(text: str, source: str = "<memory>") -> ScanReport:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ComposeFileError(f"Could not parse Compose YAML: {exc.__class__.__name__}.") from exc

    if not isinstance(document, Mapping):
        raise ComposeFileError("Compose document must be a YAML object.")
    services = document.get("services")
    if not isinstance(services, Mapping) or not services:
        raise ComposeFileError("Compose document must define at least one service.")

    findings: list[Finding] = []
    for name, service in services.items():
        if not isinstance(service, Mapping):
            raise ComposeFileError(f"Service {name!r} must be a YAML object.")
        _scan_service(str(name), service, findings)

    findings.sort(key=lambda item: (-SEVERITY_ORDER[item.severity], item.location, item.rule_id))
    return ScanReport(source=source, findings=tuple(findings))


def scan_file(path: str) -> ScanReport:
    from pathlib import Path

    file_path = Path(path)
    try:
        size = file_path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ComposeFileError(f"Compose file exceeds the {MAX_FILE_BYTES}-byte scan limit.")
        content = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ComposeFileError(f"Could not read Compose file: {exc.__class__.__name__}.") from exc
    return scan_text(content, source=str(file_path))
