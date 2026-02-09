from __future__ import annotations
import re
from deluge.core.models import ScanResult, HostInfo, PortInfo
from .base import BaseParser
from . import ParserFactory


@ParserFactory.register
class RustscanStdoutParser(BaseParser):
    @property
    def name(self) -> str:
        return "rustscan_stdout"

    def can_parse(self, content: str) -> bool:
        """Checks if the content is Rustscan stdout."""
        return "RustScan" in content and "Open" in content

    def parse(self, content: str) -> ScanResult:
        hosts_dict = {}

        # 1. Match "192.168.1.1 -> [80, 443]"
        multi_port_matches = re.findall(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+->\s+\[([\d,\s]+)\]", content
        )
        for ip, ports_str in multi_port_matches:
            if ip not in hosts_dict:
                hosts_dict[ip] = HostInfo(address=ip, status="up")

            ports = [p.strip() for p in ports_str.replace(",", " ").split()]
            for port in ports:
                if port and port not in [str(p.portid) for p in hosts_dict[ip].ports]:
                    hosts_dict[ip].ports.append(
                        PortInfo(portid=int(port), protocol="tcp", state="open")
                    )

        # 2. Match "Open 192.168.1.1:80"
        single_port_matches = re.findall(
            r"Open\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)", content
        )
        for ip, port in single_port_matches:
            if ip not in hosts_dict:
                hosts_dict[ip] = HostInfo(address=ip, status="up")

            if port not in [str(p.portid) for p in hosts_dict[ip].ports]:
                hosts_dict[ip].ports.append(
                    PortInfo(portid=int(port), protocol="tcp", state="open")
                )

        return ScanResult(
            nmap_version="Rustscan (Nmap compatible)",
            args="Unknown (Rustscan)",
            start_time="Unknown",
            hosts=list(hosts_dict.values()),
        )
