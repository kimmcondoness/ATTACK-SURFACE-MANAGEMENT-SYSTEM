from typing import Any, Dict, List

from scanner.base import BaseScanner, ScannerResult


class SubfinderScanner(BaseScanner):
    binary_name = "subfinder"
    timeout_seconds = 90

    def build_command(self, target: str) -> List[str]:
        return [self.binary_name, "-d", target, "-silent"]

    def parse_output(self, raw_output: str, target: str) -> List[Dict[str, Any]]:
        subdomains = [line.strip() for line in raw_output.splitlines() if line.strip()]
        return [{"subdomain": sub, "url": f"https://{sub}"} for sub in subdomains]

    def mock_result(self, target: str) -> ScannerResult:
        data = [
            {"subdomain": f"www.{target}", "url": f"https://www.{target}"},
            {"subdomain": f"api.{target}", "url": f"https://api.{target}"},
            {"subdomain": f"mail.{target}", "url": f"https://mail.{target}"},
        ]
        return ScannerResult(success=True, source="mock", data=data)
