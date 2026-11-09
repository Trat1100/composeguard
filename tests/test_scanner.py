import json

import pytest

from composeguard.scanner import ComposeFileError, scan_text
from composeguard.cli import main


def test_flags_privilege_plaintext_secret_socket_and_open_port_without_leaking_values():
    private_value = "never-print-this-test-value"
    report = scan_text(
        f"""
services:
  app:
    image: example/app:latest
    privileged: true
    environment:
      API_TOKEN: {private_value}
    ports:
      - "8080:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
    )

    ids = {finding.rule_id for finding in report.findings}
    assert {"privileged-container", "inline-secret", "public-port-binding", "sensitive-host-mount", "mutable-image-tag"} <= ids
    assert private_value not in json.dumps(report.to_dict())


def test_allows_interpolated_secret_and_loopback_published_port():
    report = scan_text(
        """
services:
  app:
    image: example/app:1.4.2
    environment:
      API_TOKEN: ${APP_API_TOKEN:?set APP_API_TOKEN}
    ports:
      - "127.0.0.1:8080:80"
    healthcheck:
      test: ["CMD", "true"]
"""
    )

    assert "inline-secret" not in {finding.rule_id for finding in report.findings}
    assert "public-port-binding" not in {finding.rule_id for finding in report.findings}
    assert "mutable-image-tag" not in {finding.rule_id for finding in report.findings}


@pytest.mark.parametrize("text", ["", "services: []", "services:\n  app: nope\n"])
def test_rejects_invalid_or_unsupported_compose_documents(text):
    with pytest.raises(ComposeFileError):
        scan_text(text)


def test_cli_json_and_fail_threshold(tmp_path, capsys):
    compose_file = tmp_path / "compose.yaml"
    compose_file.write_text("services:\n  app:\n    image: example/app\n", encoding="utf-8")

    exit_code = main([str(compose_file), "--format", "json", "--fail-on", "warning"])

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert output["source"] == str(compose_file)
    assert output["summary"]["warning"] >= 1
