import json
from typing import Any, Dict, List

from scanner.base import BaseScanner, ScannerResult


class NucleiScanner(BaseScanner):
    binary_name = "nuclei"
    timeout_seconds = 180

    def build_command(self, target: str) -> List[str]:
        return [self.binary_name, "-u", target, "-jsonl", "-silent"]

    def parse_output(self, raw_output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = record.get("info", {})
            findings.append(
                {
                    "severity": info.get("severity", "low"),
                    "cve": ",".join(info.get("classification", {}).get("cve-id", []) or []) or None,
                    "title": info.get("name", "Unnamed finding"),
                    "description": info.get("description", ""),
                    "recommendation": info.get("remediation", ""),
                }
            )
        return findings

    def mock_result(self, target: str) -> ScannerResult:
        data = [
            {
                "severity": "medium",
                "cve": None,
                "title": "Missing security headers",
                "description": f"{target} does not set recommended security headers (CSP, X-Frame-Options).",
                "recommendation": "Add Content-Security-Policy and X-Frame-Options headers.",
            },
            {
                "severity": "low",
                "cve": None,
                "title": "Server version disclosure",
                "description": f"{target} exposes server version information in HTTP response headers.",
                "recommendation": "Suppress version banners in server configuration.",
            },
        ]
        return ScannerResult(success=True, source="mock", data=data)
