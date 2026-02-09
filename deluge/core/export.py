import json
import csv
import threading
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from deluge.core.models import ScanResult

logger = logging.getLogger(__name__)


class ExportManager:
    """
    Manages multi-format export of scan results.
    Thread-safe and supports JSON, CSV, HTML, XML, and text formats.
    """

    def __init__(self, base_dir: str):
        """
        Initialize export manager with base directory.
        Creates a timestamped scan directory: scan_YYYYMMDD_HHMMSS
        """
        self.base_dir = Path(base_dir)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.export_dir = self.base_dir / f"scan_{timestamp}"
        self._lock = threading.Lock()
        self._initialized = False

    def _ensure_initialized(self) -> None:
        """Create export directory if it doesn't exist (thread-safe)."""
        if not self._initialized:
            with self._lock:
                if not self._initialized:
                    try:
                        self.export_dir.mkdir(parents=True, exist_ok=True)
                        self._initialized = True
                        logger.debug(f"Initialized export directory: {self.export_dir}")
                    except Exception as e:
                        logger.error(
                            f"Failed to create export directory {self.export_dir}: {e}"
                        )
                        raise

    def export_json(self, result: ScanResult, filename: str = "scan.json") -> str:
        """
        Export scan result to JSON format.
        Uses result.model_dump(mode='json') for Pydantic v2 compatibility.
        """
        try:
            self._ensure_initialized()
            file_path = self.export_dir / filename

            # Pydantic v2 model_dump(mode='json') handles datetime and other types
            data = result.model_dump(mode="json")

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            logger.info(f"Exported JSON to {file_path}")
            return str(file_path)
        except Exception as e:
            logger.error(f"Failed to export JSON: {e}")
            return ""

    def export_csv(self, result: ScanResult, filename: str = "scan.csv") -> str:
        """
        Create a flattened CSV with columns:
        IP, Hostname, Port, Protocol, State, Service, Version, Product, OS, Scripts
        One row per port found.
        """
        try:
            self._ensure_initialized()
            file_path = self.export_dir / filename

            fieldnames = [
                "IP",
                "Hostname",
                "Port",
                "Protocol",
                "State",
                "Service",
                "Version",
                "Product",
                "OS",
                "Scripts",
            ]

            rows = []
            for host in result.hosts:
                ip = str(host.address)
                hostname = host.hostnames[0] if host.hostnames else ""

                # Get OS info (first match)
                os_info = ""
                if host.os and host.os.matches:
                    os_info = host.os.matches[0].name
                elif host.os_matches:
                    os_info = host.os_matches[0]

                if not host.ports:
                    # Host with no open ports
                    rows.append(
                        {
                            "IP": ip,
                            "Hostname": hostname,
                            "Port": "",
                            "Protocol": "",
                            "State": host.status,
                            "Service": "",
                            "Version": "",
                            "Product": "",
                            "OS": os_info,
                            "Scripts": "",
                        }
                    )
                    continue

                for port in host.ports:
                    service_name = ""
                    version = ""
                    product = ""

                    if port.service:
                        service_name = port.service.name or ""
                        version = port.service.version or ""
                        product = port.service.product or ""
                    else:
                        service_name = port.service_name or ""
                        version = port.version or ""
                        product = port.product or ""

                    # Combine scripts into a JSON string
                    scripts_data = {}
                    if port.script_results:
                        scripts_data = {s.id: s.output for s in port.script_results}
                    elif port.scripts:
                        scripts_data = port.scripts

                    scripts_json = json.dumps(scripts_data) if scripts_data else ""

                    rows.append(
                        {
                            "IP": ip,
                            "Hostname": hostname,
                            "Port": port.portid,
                            "Protocol": port.protocol,
                            "State": port.state,
                            "Service": service_name,
                            "Version": version,
                            "Product": product,
                            "OS": os_info,
                            "Scripts": scripts_json,
                        }
                    )

            with open(file_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

            logger.info(f"Exported CSV to {file_path}")
            return str(file_path)
        except Exception as e:
            logger.error(f"Failed to export CSV: {e}")
            return ""

    def export_html(self, result: ScanResult, filename: str = "scan.html") -> str:
        """
        Create a standalone HTML report with inline CSS.
        """
        try:
            self._ensure_initialized()
            file_path = self.export_dir / filename

            css = """
            /* Catppuccin Mocha Theme - https://catppuccin.com/palette */
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #cdd6f4; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #1e1e2e; }
            h1, h2, h3 { color: #cdd6f4; }
            .header { background: #181825; color: #cdd6f4; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
            .summary-card { background: #313244; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.3); margin-bottom: 20px; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 20px; background: #313244; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.3); }
            th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #585b70; }
            th { background-color: #45475a; color: #cdd6f4; }
            tr:hover { background-color: #45475a; }
            .state-open { color: #a6e3a1; font-weight: bold; }
            .state-closed { color: #f38ba8; }
            .state-filtered { color: #f9e2af; }
            .host-section { background: #313244; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.3); margin-bottom: 30px; }
            .script-output { background: #45475a; border-left: 4px solid #89b4fa; padding: 10px; margin: 10px 0; font-family: monospace; white-space: pre-wrap; font-size: 0.9em; color: #cdd6f4; }
            .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; }
            .badge-up { background: #313244; color: #a6e3a1; }
            .badge-down { background: #313244; color: #f38ba8; }
            code { background: #45475a; color: #fab387; padding: 2px 6px; border-radius: 4px; }
            a { color: #89b4fa; }
            strong { color: #cdd6f4; }
            """

            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deluge Scan Report</title>
    <style>{css}</style>
</head>
<body>
    <div class="header">
        <h1>Deluge Scan Report</h1>
        <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>

    <div class="summary-card">
        <h2>Scan Information</h2>
        <p><strong>Nmap Version:</strong> {result.nmap_version}</p>
        <p><strong>Arguments:</strong> <code>{result.args}</code></p>
        <p><strong>Start Time:</strong> {result.start_time}</p>
        <p><strong>Elapsed Time:</strong> {result.elapsed_time or "N/A"} seconds</p>
        <p><strong>Hosts Scanned:</strong> {len(result.hosts)}</p>
    </div>

    <h2>Hosts Summary</h2>
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>Status</th>
                <th>Open Ports</th>
                <th>OS</th>
            </tr>
        </thead>
        <tbody>
"""
            for host in result.hosts:
                hostname = host.hostnames[0] if host.hostnames else "N/A"
                status_class = "badge-up" if host.status == "up" else "badge-down"
                open_ports = len([p for p in host.ports if p.state == "open"])

                os_info = "N/A"
                if host.os and host.os.matches:
                    os_info = host.os.matches[0].name
                elif host.os_matches:
                    os_info = host.os_matches[0]

                html_content += f"""
            <tr>
                <td><strong>{host.address}</strong></td>
                <td>{hostname}</td>
                <td><span class="badge {status_class}">{host.status}</span></td>
                <td>{open_ports}</td>
                <td>{os_info}</td>
            </tr>"""

            html_content += """
        </tbody>
    </table>

    <h2>Detailed Results</h2>
"""
            for host in result.hosts:
                os_info = "N/A"
                if host.os and host.os.matches:
                    os_info = host.os.matches[0].name
                elif host.os_matches:
                    os_info = host.os_matches[0]

                html_content += f"""
    <div class="host-section">
        <h3>Host: {host.address} ({host.hostnames[0] if host.hostnames else "No hostname"})</h3>
        <p><strong>Status:</strong> {host.status} | <strong>OS:</strong> {os_info}</p>
"""
                if host.ports:
                    html_content += """
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
"""
                    for port in host.ports:
                        state_class = f"state-{port.state}"

                        service_name = ""
                        version = ""
                        if port.service:
                            service_name = port.service.name or ""
                            version = f"{port.service.product or ''} {port.service.version or ''}".strip()
                        else:
                            service_name = port.service_name or ""
                            version = (
                                f"{port.product or ''} {port.version or ''}".strip()
                            )

                        html_content += f"""
                <tr>
                    <td>{port.portid}</td>
                    <td>{port.protocol}</td>
                    <td><span class="{state_class}">{port.state}</span></td>
                    <td>{service_name}</td>
                    <td>{version}</td>
                </tr>"""

                        # Add script results if any
                        scripts = []
                        if port.script_results:
                            scripts = port.script_results
                        elif port.scripts:
                            # Convert legacy scripts dict to ScriptResult-like objects for display
                            from deluge.core.models import ScriptResult

                            scripts = [
                                ScriptResult(id=k, output=v)
                                for k, v in port.scripts.items()
                            ]

                        if scripts:
                            html_content += """
                <tr>
                    <td colspan="5">
                        <div style="margin-left: 20px;">
                            <strong>Script Results:</strong>"""
                            for script in scripts:
                                html_content += f"""
                            <div class="script-output"><strong>{script.id}:</strong><br>{script.output}</div>"""
                            html_content += """
                        </div>
                    </td>
                </tr>"""

                    html_content += """
            </tbody>
        </table>"""
                else:
                    html_content += "<p>No open ports found.</p>"

                html_content += "</div>"

            html_content += """
</body>
</html>"""

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            logger.info(f"Exported HTML to {file_path}")
            return str(file_path)
        except Exception as e:
            logger.error(f"Failed to export HTML: {e}")
            return ""

    def export_xml(self, result: ScanResult, filename: str = "scan.xml") -> str:
        """
        Export basic XML structure from result data.
        """
        try:
            self._ensure_initialized()
            file_path = self.export_dir / filename

            # Reconstruct a basic XML structure
            xml_lines = [
                '<?xml version="1.0" encoding="UTF-8"?>',
                "<!-- Deluge Scan Result -->",
                f'<nmaprun scanner="deluge" args="{result.args}" version="{result.nmap_version}" startstr="{result.start_time}">',
            ]

            for host in result.hosts:
                xml_lines.append(f'  <host status="{host.status}">')
                xml_lines.append(
                    f'    <address addr="{host.address}" addrtype="ipv4"/>'
                )
                if host.hostnames:
                    xml_lines.append("    <hostnames>")
                    for name in host.hostnames:
                        xml_lines.append(f'      <hostname name="{name}" type="user"/>')
                    xml_lines.append("    </hostnames>")

                if host.ports:
                    xml_lines.append("    <ports>")
                    for port in host.ports:
                        xml_lines.append(
                            f'      <port protocol="{port.protocol}" portid="{port.portid}">'
                        )
                        xml_lines.append(
                            f'        <state state="{port.state}" reason="syn-ack" reason_ttl="0"/>'
                        )

                        service_name = ""
                        product = ""
                        version = ""
                        if port.service:
                            service_name = port.service.name or ""
                            product = port.service.product or ""
                            version = port.service.version or ""
                        else:
                            service_name = port.service_name or ""
                            product = port.product or ""
                            version = port.version or ""

                        xml_lines.append(
                            f'        <service name="{service_name}" product="{product}" version="{version}" method="probed" conf="10"/>'
                        )

                        scripts = port.script_results or []
                        if not scripts and port.scripts:
                            from deluge.core.models import ScriptResult

                            scripts = [
                                ScriptResult(id=k, output=v)
                                for k, v in port.scripts.items()
                            ]

                        for script in scripts:
                            xml_lines.append(
                                f'        <script id="{script.id}" output="{script.output}"/>'
                            )

                        xml_lines.append("      </port>")
                    xml_lines.append("    </ports>")

                # OS Info
                os_info = None
                if host.os and host.os.matches:
                    os_info = host.os.matches[0]

                if os_info:
                    xml_lines.append("    <os>")
                    xml_lines.append(
                        f'      <osmatch name="{os_info.name}" accuracy="{os_info.accuracy}" line="0">'
                    )
                    for os_class in os_info.classes:
                        xml_lines.append(
                            f'        <osclass type="{os_class.type}" vendor="{os_class.vendor}" osfamily="{os_class.osfamily}" osgen="{os_class.osgen or ""}" accuracy="{os_class.accuracy}"/>'
                        )
                    xml_lines.append("      </osmatch>")
                    xml_lines.append("    </os>")
                elif host.os_matches:
                    xml_lines.append("    <os>")
                    xml_lines.append(
                        f'      <osmatch name="{host.os_matches[0]}" accuracy="100" line="0"/>'
                    )
                    xml_lines.append("    </os>")

                xml_lines.append("  </host>")

            xml_lines.append("</nmaprun>")

            with open(file_path, "w", encoding="utf-8") as f:
                f.write("\n".join(xml_lines))

            logger.info(f"Exported XML to {file_path}")
            return str(file_path)
        except Exception as e:
            logger.error(f"Failed to export XML: {e}")
            return ""

    def export_text(self, result: ScanResult, filename: str = "scan.txt") -> str:
        """
        Create a human-readable text summary.
        """
        try:
            self._ensure_initialized()
            file_path = self.export_dir / filename

            lines = [
                "Deluge Scan Summary",
                "=" * 50,
                f"Nmap Version: {result.nmap_version}",
                f"Arguments:    {result.args}",
                f"Start Time:   {result.start_time}",
                f"Elapsed:      {result.elapsed_time or 'N/A'} seconds",
                f"Hosts Found:  {len(result.hosts)}",
                "",
            ]

            for host in result.hosts:
                hostname = f" ({host.hostnames[0]})" if host.hostnames else ""
                lines.append(f"Host: {host.address}{hostname}")
                lines.append(f"Status: {host.status}")

                os_info = "N/A"
                if host.os and host.os.matches:
                    os_info = host.os.matches[0].name
                elif host.os_matches:
                    os_info = host.os_matches[0]
                lines.append(f"OS: {os_info}")

                if host.ports:
                    lines.append("PORT      STATE  SERVICE  VERSION")
                    for port in host.ports:
                        service_name = ""
                        version = ""
                        if port.service:
                            service_name = port.service.name or ""
                            version = f"{port.service.product or ''} {port.service.version or ''}".strip()
                        else:
                            service_name = port.service_name or ""
                            version = (
                                f"{port.product or ''} {port.version or ''}".strip()
                            )

                        port_str = f"{port.portid}/{port.protocol}"
                        lines.append(
                            f"{port_str:<9} {port.state:<6} {service_name:<8} {version}"
                        )

                        scripts = port.script_results or []
                        if not scripts and port.scripts:
                            from deluge.core.models import ScriptResult

                            scripts = [
                                ScriptResult(id=k, output=v)
                                for k, v in port.scripts.items()
                            ]

                        for script in scripts:
                            lines.append(f"|_ {script.id}: {script.output}")
                else:
                    lines.append("No open ports found.")
                lines.append("")

            with open(file_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))

            logger.info(f"Exported text summary to {file_path}")
            return str(file_path)
        except Exception as e:
            logger.error(f"Failed to export text: {e}")
            return ""

    def export_all(self, result: ScanResult, formats: List[str]) -> Dict[str, str]:
        """
        Orchestrate multiple exports.
        Return dict mapping format -> file path.
        """
        results = {}
        format_map = {
            "json": self.export_json,
            "csv": self.export_csv,
            "html": self.export_html,
            "xml": self.export_xml,
            "txt": self.export_text,
        }

        for fmt in formats:
            fmt_lower = fmt.lower()
            if fmt_lower in format_map:
                path = format_map[fmt_lower](result)
                if path:
                    results[fmt_lower] = path
            else:
                logger.warning(f"Unsupported export format: {fmt}")

        return results

    def export_port_scan(
        self,
        ip: str,
        port: int,
        protocol: str,
        xml_content: str,
        nmap_content: str = None,
    ) -> None:
        """
        Keep existing functionality for per-port exports in interactive mode.
        Save individual port XML files.
        """
        try:
            self._ensure_initialized()

            # Create IP subdirectory
            ip_dir = self.export_dir / ip.replace(".", "_")
            ip_dir.mkdir(exist_ok=True)

            # Save XML file
            xml_filename = f"port_{port}_{protocol}.xml"
            xml_path = ip_dir / xml_filename
            with open(xml_path, "w", encoding="utf-8") as f:
                f.write(xml_content)

            # Save text file if provided
            if nmap_content:
                nmap_filename = f"port_{port}_{protocol}.nmap"
                nmap_path = ip_dir / nmap_filename
                with open(nmap_path, "w", encoding="utf-8") as f:
                    f.write(nmap_content)

            logger.debug(f"Exported scan for {ip}:{port} to {ip_dir}")

        except Exception as e:
            logger.error(f"Failed to export scan for {ip}:{port}: {e}")
