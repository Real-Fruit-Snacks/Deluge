from __future__ import annotations
import re
from deluge.core.models import (
    ScanResult,
    HostInfo,
    PortInfo,
    ServiceMetadata,
    OSInfo,
    OSMatch,
    ScriptResult,
    Traceroute,
    Hop,
)
from .base import BaseParser
from . import ParserFactory


@ParserFactory.register
class NmapStdoutParser(BaseParser):
    @property
    def name(self) -> str:
        return "nmap_stdout"

    def can_parse(self, content: str) -> bool:
        """Checks if the content is Nmap stdout."""
        return "Starting Nmap" in content and "Nmap scan report for" in content

    def parse(self, content: str) -> ScanResult:
        nmap_version = "Unknown"
        version_match = re.search(r"Starting Nmap (\d+\.\d+)", content)
        if version_match:
            nmap_version = version_match.group(1)

        hosts = []
        host_reports = re.split(r"Nmap scan report for ", content)[1:]

        for report in host_reports:
            lines = report.split("\n")
            header = lines[0].strip()

            address_match = re.search(
                r"\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?", header
            )
            address = address_match.group(1) if address_match else header.split()[-1]

            hostnames = []
            if address_match and header.split()[0] != address:
                hostnames.append(header.split()[0])

            ports_list = []
            os_info = None
            os_matches_legacy = []
            traceroute = None
            host_scripts = []

            current_port = None
            in_traceroute = False

            i = 0
            while i < len(lines):
                line = lines[i].rstrip()
                if not line:
                    i += 1
                    continue

                if "PORT" in line and "STATE" in line and "SERVICE" in line:
                    in_traceroute = False
                    i += 1
                    continue

                port_match = re.match(
                    r"^(\d+)/(\w+)\s+(\w+)\s+([^\s|]+)\s*(.*)", line.strip()
                )
                if port_match:
                    portid, protocol, state, service_name, version_info = (
                        port_match.groups()
                    )

                    product = None
                    version = None
                    extrainfo = None

                    if version_info:
                        v_match = re.match(
                            r"^([^(\[]+)(?:[ (]([^)]+)\)?.*)?", version_info.strip()
                        )
                        if v_match:
                            product = v_match.group(1).strip()
                            version = (
                                v_match.group(2).strip() if v_match.group(2) else None
                            )
                            if "(" in version_info:
                                extrainfo = version_info[
                                    version_info.find("(") :
                                ].strip()

                    current_port = PortInfo(
                        portid=int(portid),
                        protocol=protocol,
                        state=state,
                        service_name=service_name,
                        service=ServiceMetadata(
                            name=service_name,
                            product=product,
                            version=version,
                            extrainfo=extrainfo,
                        ),
                        product=product,
                        version=version,
                        extrainfo=extrainfo,
                    )
                    ports_list.append(current_port)
                    i += 1
                    continue

                if (
                    line.strip().startswith("|") or line.strip().startswith("|_")
                ) and current_port:
                    script_id_match = re.match(r"^[|_ ]+([^:]+):(.*)", line.strip())
                    if script_id_match:
                        script_id = script_id_match.group(1).strip()
                        script_lines = []
                        first_line_data = script_id_match.group(2).strip()
                        if first_line_data:
                            script_lines.append(first_line_data)

                        i += 1
                        while (
                            i < len(lines)
                            and lines[i].strip().startswith("|")
                            and not lines[i].strip().startswith("|_")
                        ):
                            sub_data = lines[i].strip()[1:].strip()
                            if sub_data:
                                script_lines.append(sub_data)
                            i += 1

                        if i < len(lines) and lines[i].strip().startswith("|_"):
                            sub_data = lines[i].strip()[2:].strip()
                            if sub_data:
                                script_lines.append(sub_data)
                            i += 1

                        output = "\n".join(script_lines)
                        current_port.script_results.append(
                            ScriptResult(id=script_id, output=output)
                        )
                        current_port.scripts[script_id] = output
                        continue
                    else:
                        # Handle continuation lines that don't have a colon (e.g. multi-line script output)
                        # This shouldn't happen with the logic above but just in case
                        i += 1
                        continue

                os_match = re.search(r"OS details: (.*)", line)
                if not os_match:
                    os_match = re.search(r"Aggressive OS guesses: (.*)", line)

                if os_match:
                    os_str = os_match.group(1)
                    os_matches_legacy.append(os_str)

                    matches = []
                    for part in os_str.split(", "):
                        name_acc = re.match(r"(.*) \((\d+)%\)", part)
                        if name_acc:
                            name, acc = name_acc.groups()
                            matches.append(OSMatch(name=name, accuracy=int(acc)))
                        else:
                            matches.append(OSMatch(name=part, accuracy=100))

                    os_info = OSInfo(matches=matches)
                    i += 1
                    continue

                if "TRACEROUTE" in line:
                    in_traceroute = True
                    proto_match = re.search(r"using port (\d+)/(\w+)", line)
                    traceroute = Traceroute(
                        port=int(proto_match.group(1)) if proto_match else None,
                        proto=proto_match.group(2) if proto_match else None,
                        hops=[],
                    )
                    i += 1
                    continue

                if in_traceroute and re.match(r"^\s*\d+\s+[\d.]+\s+ms", line.strip()):
                    hop_match = re.match(
                        r"^\s*(\d+)\s+([\d.]+)\s+ms\s+([^\s]+)\s*(.*)", line.strip()
                    )
                    if hop_match:
                        ttl, rtt, ipaddr, hostname = hop_match.groups()
                        traceroute.hops.append(
                            Hop(
                                ttl=int(ttl),
                                rtt=float(rtt),
                                ipaddr=ipaddr,
                                host=hostname if hostname else None,
                            )
                        )
                    i += 1
                    continue

                if line.startswith("Host script results:"):
                    i += 1
                    while i < len(lines) and (
                        lines[i].strip().startswith("|")
                        or lines[i].strip().startswith("|_")
                    ):
                        h_line = lines[i].strip()
                        h_script_match = re.match(r"^[|_ ]+([^:]+):(.*)", h_line)
                        if h_script_match:
                            h_script_id = h_script_match.group(1).strip()
                            h_script_lines = []
                            first_h_data = h_script_match.group(2).strip()
                            if first_h_data:
                                h_script_lines.append(first_h_data)

                            i += 1
                            while (
                                i < len(lines)
                                and lines[i].strip().startswith("|")
                                and not lines[i].strip().startswith("|_")
                            ):
                                h_script_lines.append(lines[i].strip()[1:].strip())
                                i += 1
                            if i < len(lines) and lines[i].strip().startswith("|_"):
                                h_script_lines.append(lines[i].strip()[2:].strip())
                                i += 1

                            h_output = "\n".join(filter(None, h_script_lines))
                            host_scripts.append(
                                ScriptResult(id=h_script_id, output=h_output)
                            )
                        else:
                            i += 1
                    continue

                i += 1

            hosts.append(
                HostInfo(
                    address=address,
                    status="up",
                    hostnames=hostnames,
                    ports=ports_list,
                    os=os_info,
                    os_matches=os_matches_legacy,
                    traceroute=traceroute,
                    hostscript_results=host_scripts,
                )
            )

        return ScanResult(
            nmap_version=nmap_version,
            args="Unknown (stdout)",
            start_time="Unknown",
            hosts=hosts,
        )
