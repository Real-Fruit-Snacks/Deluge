from __future__ import annotations
import xml.etree.ElementTree as ET
from typing import Optional, Any
from deluge.core.models import (
    ScanResult,
    HostInfo,
    PortInfo,
    OSInfo,
    OSMatch,
    OSClass,
    ServiceMetadata,
    ScriptResult,
    Traceroute,
    Hop,
)
from .base import BaseParser
from . import ParserFactory


@ParserFactory.register
class NmapXmlParser(BaseParser):
    @property
    def name(self) -> str:
        return "nmap_xml"

    def can_parse(self, content: str) -> bool:
        return "<nmaprun" in content and "<host" in content

    def parse(self, content: str) -> ScanResult:
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            # Handle cases where content might be a file path
            try:
                tree = ET.parse(content)
                root = tree.getroot()
            except Exception:
                raise ValueError("Could not parse XML content")

        nmap_version = root.get("version", "Unknown")
        args = root.get("args", "")
        start_time = root.get("startstr", "")

        hosts = []
        for host_node in root.findall("host"):
            hosts.append(self._parse_host(host_node))

        finished_node = root.find("runstats/finished")
        elapsed_time = None
        summary = ""
        if finished_node is not None:
            elapsed_time = float(finished_node.get("elapsed", 0))
            summary = finished_node.get("summary", "")

        return ScanResult(
            nmap_version=nmap_version,
            args=args,
            start_time=start_time,
            hosts=hosts,
            elapsed_time=elapsed_time,
            summary=summary,
        )

    def _parse_host(self, node: ET.Element) -> HostInfo:
        address = node.find("address").get("addr")
        status_node = node.find("status")
        status = status_node.get("state") if status_node is not None else "unknown"

        hostnames = []
        for hn in node.findall("hostnames/hostname"):
            hostnames.append(hn.get("name"))

        ports = []
        for port_node in node.findall("ports/port"):
            ports.append(self._parse_port(port_node))

        # OS Detection
        os_info = self._parse_os(node.find("os"))
        os_matches = [m.name for m in os_info.matches] if os_info else []

        # Distance & Traceroute
        distance_node = node.find("distance")
        distance = (
            int(distance_node.get("value")) if distance_node is not None else None
        )

        traceroute = self._parse_traceroute(node.find("trace"))

        # Host Scripts
        hostscript_results = []
        for script_node in node.findall("hostscript/script"):
            hostscript_results.append(self._parse_script(script_node))

        return HostInfo(
            address=address,
            status=status,
            hostnames=hostnames,
            ports=ports,
            os=os_info,
            os_matches=os_matches,
            distance=distance,
            traceroute=traceroute,
            hostscript_results=hostscript_results,
        )

    def _parse_port(self, node: ET.Element) -> PortInfo:
        portid = int(node.get("portid"))
        protocol = node.get("protocol")

        state_node = node.find("state")
        state = state_node.get("state") if state_node is not None else "unknown"
        reason = state_node.get("reason") if state_node is not None else None
        reason_ttl = (
            int(state_node.get("reason_ttl"))
            if state_node is not None and state_node.get("reason_ttl")
            else None
        )

        service_node = node.find("service")
        service_meta = None
        if service_node is not None:
            cpes = [c.text for c in service_node.findall("cpe")]
            service_meta = ServiceMetadata(
                name=service_node.get("name"),
                product=service_node.get("product"),
                version=service_node.get("version"),
                extrainfo=service_node.get("extrainfo"),
                ostype=service_node.get("ostype"),
                conf=int(service_node.get("conf"))
                if service_node.get("conf")
                else None,
                method=service_node.get("method"),
                tunnel=service_node.get("tunnel"),
                cpes=cpes,
            )

        script_results = []
        scripts_dict = {}
        for script_node in node.findall("script"):
            res = self._parse_script(script_node)
            script_results.append(res)
            scripts_dict[res.id] = res.output

        return PortInfo(
            portid=portid,
            protocol=protocol,
            state=state,
            reason=reason,
            reason_ttl=reason_ttl,
            service=service_meta,
            script_results=script_results,
            # Legacy fields
            service_name=service_meta.name if service_meta else None,
            product=service_meta.product if service_meta else None,
            version=service_meta.version if service_meta else None,
            extrainfo=service_meta.extrainfo if service_meta else None,
            scripts=scripts_dict,
        )

    def _parse_os(self, node: Optional[ET.Element]) -> Optional[OSInfo]:
        if node is None:
            return None

        matches = []
        for match_node in node.findall("osmatch"):
            classes = []
            for class_node in match_node.findall("osclass"):
                cpes = [c.text for c in class_node.findall("cpe")]
                classes.append(
                    OSClass(
                        type=class_node.get("type"),
                        vendor=class_node.get("vendor"),
                        osfamily=class_node.get("osfamily"),
                        osgen=class_node.get("osgen"),
                        accuracy=int(class_node.get("accuracy")),
                        cpes=cpes,
                    )
                )

            matches.append(
                OSMatch(
                    name=match_node.get("name"),
                    accuracy=int(match_node.get("accuracy")),
                    classes=classes,
                )
            )

        fingerprint_node = node.find("osfingerprint")
        fingerprint = (
            fingerprint_node.get("fingerprint")
            if fingerprint_node is not None
            else None
        )

        return OSInfo(matches=matches, fingerprint=fingerprint)

    def _parse_traceroute(self, node: Optional[ET.Element]) -> Optional[Traceroute]:
        if node is None:
            return None

        hops = []
        for hop_node in node.findall("hop"):
            hops.append(
                Hop(
                    ttl=int(hop_node.get("ttl")),
                    ipaddr=hop_node.get("ipaddr"),
                    rtt=float(hop_node.get("rtt")) if hop_node.get("rtt") else None,
                    host=hop_node.get("host"),
                )
            )

        return Traceroute(
            port=int(node.get("port")) if node.get("port") else None,
            proto=node.get("proto"),
            hops=hops,
        )

    def _parse_script(self, node: ET.Element) -> ScriptResult:
        script_id = node.get("id")
        output = node.get("output")

        data = {}
        # Parse elements and tables recursively
        for child in node:
            if child.tag == "elem":
                key = child.get("key")
                if key:
                    data[key] = child.text
                else:
                    # If no key, it might be a list item or a single value
                    if "values" not in data:
                        data["values"] = []
                    data["values"].append(child.text)
            elif child.tag == "table":
                key = child.get("key")
                table_data = self._parse_script_table(child)
                if key:
                    data[key] = table_data
                else:
                    if "tables" not in data:
                        data["tables"] = []
                    data["tables"].append(table_data)

        # Flatten data if it only contains "values" or "tables" and they are simple
        if len(data) == 1:
            if "values" in data:
                data = data["values"]
            elif "tables" in data:
                data = data["tables"]

        return ScriptResult(id=script_id, output=output, data=data)

    def _parse_script_table(self, node: ET.Element) -> Any:
        data = {}
        has_keys = False
        elements = []
        tables = []

        for child in node:
            if child.tag == "elem":
                key = child.get("key")
                if key:
                    data[key] = child.text
                    has_keys = True
                else:
                    elements.append(child.text)
            elif child.tag == "table":
                key = child.get("key")
                table_data = self._parse_script_table(child)
                if key:
                    data[key] = table_data
                    has_keys = True
                else:
                    tables.append(table_data)

        if not has_keys:
            if tables and not elements:
                return tables
            if elements and not tables:
                return elements
            if elements or tables:
                return {"elements": elements, "tables": tables}
            return {}

        if elements:
            data["elements"] = elements
        if tables:
            data["tables"] = tables

        return data
