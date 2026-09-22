import re
from typing import Any, Dict, List

from scanner.base import BaseScanner, ScannerResult


# nmap's -oG "Ports:" field is port/state/protocol/owner/service/rpc_info/version/
# -- owner and rpc_info are effectively always empty for a plain -sV scan, so
# they show up as the doubled "//" below rather than as capture groups.
_PORT_RE = re.compile(r"(\d+)/(open|closed|filtered)/(\w+)//([^/]*)//([^/]*)/")


class NmapScanner(BaseScanner):
    binary_name = "nmap"
    timeout_seconds = 300

    def build_command(self, target: str) -> List[str]:
        return [self.binary_name, "-sV", "-T4", "--top-ports", "20", "--max-retries", "1", "-oG", "-", target]

    def parse_output(self, raw_output: str, target: str) -> List[Dict[str, Any]]:
        results = []
        for line in raw_output.splitlines():
            if not line.startswith("Host:") or "Ports:" not in line:
                continue
            ports_section = line.split("Ports:", 1)[1]
            for match in _PORT_RE.finditer(ports_section):
                port, state, protocol, service, version = match.groups()
                if state != "open":
                    continue
                results.append(
                    {
                        "port": int(port),
                        "protocol": protocol,
                        "state": state,
                        "service_name": service or "unknown",
                        "service_version": version or "",
                    }
                )
        return results

    def mock_result(self, target: str) -> ScannerResult:
        data = [
            {"port": 80, "protocol": "tcp", "state": "open", "service_name": "http", "service_version": "nginx"},
            {"port": 443, "protocol": "tcp", "state": "open", "service_name": "https", "service_version": "nginx"},
            {"port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh", "service_version": "OpenSSH"},
        ]
        return ScannerResult(success=True, source="mock", data=data)
