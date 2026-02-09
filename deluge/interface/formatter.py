from __future__ import annotations
from typing import Optional, List, Any
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress
from rich import box
from deluge.core.models import ScanResult, HostInfo, PortInfo, ScriptResult


# Catppuccin Mocha Theme - https://catppuccin.com/palette
# Rosewater #f5e0dc | Flamingo #f2cdcd | Pink #f5c2e7    | Mauve   #cba6f7
# Red       #f38ba8 | Maroon  #eba0ac | Peach #fab387    | Yellow  #f9e2af
# Green     #a6e3a1 | Teal    #94e2d5 | Sky   #89dceb    | Sapphire #74c7ec
# Blue      #89b4fa | Lavender #b4befe | Text  #cdd6f4   | Subtext1 #bac2de
# Subtext0  #a6adc8 | Overlay2 #9399b2 | Overlay1 #7f849c | Overlay0 #6c7086
# Surface2  #585b70 | Surface1 #45475a | Surface0 #313244
# Base      #1e1e2e | Mantle   #181825 | Crust    #11111b


class NmapFormatter:
    def __init__(self):
        # Force UTF-8 encoding for Windows compatibility with Unicode box characters
        self.console = Console(force_terminal=True, legacy_windows=False)


    def display_warning(self, message: str) -> None:
        """Display warning messages in a Rich Panel with yellow border."""
        self.console.print(
            Panel(
                Text(f"⚠️  {message}"),
                border_style="#f9e2af",
                title="[bold #f9e2af]Warning[/]",
                padding=(1, 2),
            )
        )

    def display_error(self, message: str) -> None:
        """Display error messages in a Rich Panel with red border."""
        self.console.print(
            Panel(
                Text(f"❌ {message}"),
                border_style="#f38ba8",
                title="[bold #f38ba8]Error[/]",
                padding=(1, 2),
            )
        )

    def display_info(self, message: str) -> None:
        """Display informational messages in a Rich Panel with blue border."""
        self.console.print(
            Panel(
                Text(f"ℹ️  {message}"),
                border_style="#89b4fa",
                title="[bold #89b4fa]Information[/]",
                padding=(1, 2),
            )
        )

    def format_install_guide(self, binary: str, instruction: str) -> None:
        """Display a formatted installation guide using Rich."""
        guide_text = Text.assemble(
            ("Binary: ", "bold"),
            (f"{binary}\n", "#89dceb"),
            ("Instructions: ", "bold"),
            (instruction, "#a6e3a1"),
        )
        self.console.print(
            Panel(
                guide_text,
                title="[bold]Installation Guide[/]",
                border_style="#cba6f7",
                padding=(1, 2),
            )
        )

    def format_discovery_summary(self, discovered_ports: dict[str, list[str]]):
        """Displays all discovered ports in a single professional box."""
        if not discovered_ports:
            return

        table = Table(show_header=True, header_style="bold #89dceb", box=box.SIMPLE)
        table.add_column("Target IP", style="#f9e2af")
        table.add_column("Discovered Ports", style="#cba6f7")

        for ip, ports in discovered_ports.items():
            table.add_row(ip, ", ".join(sorted(ports, key=int)))

        self.console.print(
            Panel(
                table,
                title="[bold #a6e3a1]Discovery Phase Complete[/]",
                subtitle="[dim]Starting targeted Nmap scans...[/]",
                border_style="#a6e3a1",
                padding=(1, 2),
            )
        )

    def format_scan(self, result: ScanResult):
        # Header
        header_text = Text.assemble(
            ("Nmap Scan Results\n", "bold #89dceb"),
            (
                f"Version: {result.nmap_version} | Started: {result.start_time}\n",
                "italic",
            ),
            (f"Args: {result.args}", "dim"),
        )
        self.console.print(Panel(header_text, border_style="#89b4fa", box=box.SQUARE))

        for host in result.hosts:
            self._format_target_header(host)
            self._format_ports_table(host)

            # Domain information section
            domain_panel = self._format_domain_info(host)
            if domain_panel:
                self.console.print(domain_panel)

            if host.hostscript_results:
                self._format_host_scripts(host.hostscript_results)

            self._format_ssh_keys(host)
            self._format_ssl_certificates(host)

            if host.traceroute:
                self._format_traceroute(host)

        # Footer
        if result.summary:
            footer_text = Text.assemble(
                ("\nScan Summary\n", "bold #a6e3a1"),
                (f"{result.summary}\n", ""),
                (f"Elapsed Time: {result.elapsed_time}s", "italic"),
            )
            self.console.print(Panel(footer_text, border_style="#a6e3a1", box=box.SQUARE))

    def format_host(self, host: HostInfo):
        if host.os_matches:
            os_text = Text.assemble(
                ("OS Matches: ", "bold"), (", ".join(host.os_matches), "#cba6f7")
            )
            self.console.print(os_text)

        if host.ports:
            table = Table(show_header=True, header_style="bold #cba6f7", box=box.SIMPLE)
            table.add_column("Port", style="#89dceb")
            table.add_column("State", justify="center")
            table.add_column("Service")
            table.add_column("Version")

            for port in host.ports:
                state_style = (
                    "#a6e3a1"
                    if port.state == "open"
                    else "#f9e2af"
                    if "filtered" in port.state
                    else "#f38ba8"
                )

                version_info = []
                if port.product:
                    version_info.append(port.product)
                if port.version:
                    version_info.append(port.version)
                if port.extrainfo:
                    version_info.append(f"({port.extrainfo})")

                table.add_row(
                    f"{port.portid}/{port.protocol}",
                    Text(port.state, style=state_style),
                    port.service_name or "unknown",
                    " ".join(version_info) if version_info else "",
                )

                # Add script output if any
                if port.scripts:
                    for script_id, output in port.scripts.items():
                        # Indent script output
                        indented_output = "\n".join(
                            [f"  {line}" for line in output.strip().split("\n")]
                        )
                        table.add_row(
                            "",
                            "",
                            Text(f"|_ {script_id}", style="dim"),
                            Text(indented_output, style="dim italic"),
                        )

            self.console.print(
                Panel(
                    table,
                    title=f"Nmap Results: {host.address}",
                    border_style="#89b4fa",
                    padding=(1, 1),
                )
            )
        else:
            self.console.print(
                Panel(
                    "[italic dim]No open ports found or host is down.[/]",
                    title=f"Nmap Results: {host.address}",
                    border_style="#f38ba8",
                )
            )

    def format_interactive_summary(self, result: ScanResult):
        """Displays a final target-centric summary of all discovered hosts and ports."""
        self.console.print("\n")
        self.console.print(
            Panel(
                Text(
                    "Final Interactive Scan Summary",
                    justify="center",
                    style="bold #89dceb",
                ),
                box=box.DOUBLE,
                border_style="#89b4fa",
            )
        )

        # Sort hosts by address
        sorted_hosts = sorted(result.hosts, key=lambda h: str(h.address))
        target_colors = ["#89dceb", "#cba6f7", "#89b4fa", "#f9e2af", "#a6e3a1"]

        for idx, host in enumerate(sorted_hosts):
            color = target_colors[idx % len(target_colors)]
            target_content = []

            # 1. Header
            header = self._format_target_header(host, color=color, wrapped=False)
            if header:
                target_content.append(header)
                target_content.append(Text(""))  # Spacer

            # 2. Ports Table
            if not host.ports:
                target_content.append(
                    Text(
                        "  No open ports discovered for this target.",
                        style="italic #f38ba8",
                    )
                )
            else:
                ports_table = self._format_ports_table(host, wrapped=False)
                if ports_table:
                    target_content.append(ports_table)

            # 3. Domain information section
            domain_info = self._format_domain_info(host, color=color, wrapped=False)
            if domain_info:
                target_content.append(Text(""))  # Spacer
                target_content.append(
                    Text("Domain & Identity Information", style=f"bold {color}")
                )
                target_content.append(domain_info)

            # 4. Host-level scripts
            if host.hostscript_results:
                host_scripts = self._format_host_scripts(
                    host.hostscript_results, wrapped=False
                )
                if host_scripts:
                    target_content.append(Text(""))  # Spacer
                    target_content.append(host_scripts)

            # 5. SSH Keys (collected from port scripts)
            ssh_keys = self._format_ssh_keys(host, wrapped=False)
            if ssh_keys:
                target_content.append(Text(""))  # Spacer
                target_content.append(ssh_keys)

            # 6. SSL Certificates (collected from port scripts)
            ssl_certs = self._format_ssl_certificates(host, wrapped=False)
            if ssl_certs:
                for cert_table in ssl_certs:
                    target_content.append(Text(""))  # Spacer
                    target_content.append(cert_table)

            # 7. Traceroute
            if host.traceroute:
                topology = self._format_traceroute(host, wrapped=False)
                if topology:
                    target_content.append(Text(""))  # Spacer
                    target_content.append(topology)

            # Wrap EVERYTHING in one large Panel with the target color
            self.console.print(
                Panel(
                    Group(*target_content),
                    title=f"[bold {color}]Target: {host.address}[/bold {color}]",
                    border_style=color,
                    padding=(1, 2),
                )
            )
            self.console.print("")  # Space between targets

        # --- Final Summary Panel ---
        # Calculate summary statistics
        total_hosts = len(result.hosts)
        total_ports = sum(len(host.ports) for host in result.hosts)

        # Create summary table
        summary_table = Table(
            title="Host Overview", show_header=True, header_style="bold", box=box.SIMPLE
        )
        summary_table.add_column("IP Address", style="#89dceb")
        summary_table.add_column("Hostname", style="#a6e3a1")
        summary_table.add_column("Operating System", style="#f9e2af")
        summary_table.add_column("Ports", justify="right", style="#cba6f7")
        summary_table.add_column("Key Services", style="#89b4fa")

        for host in sorted_hosts:
            ip = str(host.address)

            # Get hostname (first match or "-")
            hostname = self._get_hostname(host)

            # Get OS (first match or "-")
            os_info = "-"
            if host.os and host.os.matches:
                os_info = host.os.matches[0].name
            elif host.os_matches:
                os_info = host.os_matches[0]

            if len(os_info) > 50:
                os_info = os_info[:47] + "..."

            # Count open ports
            port_count = str(len(host.ports))

            # Get key services (top 3-5 interesting ports)
            key_services = []
            interesting_ports = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443]

            # Look at ports
            for port in host.ports:
                if port.portid in interesting_ports or port.service_name:
                    service_name = port.service_name if port.service_name else "unknown"
                    key_services.append(f"{port.portid}/{service_name}")
                if len(key_services) >= 5:
                    break

            if not key_services and host.ports:
                # If no interesting ports, just show first few
                key_services = [
                    f"{p.portid}/{p.service_name or 'unknown'}" for p in host.ports[:3]
                ]

            services_str = ", ".join(key_services) if key_services else "-"
            if len(services_str) > 60:
                services_str = services_str[:57] + "..."

            summary_table.add_row(ip, hostname, os_info, port_count, services_str)

        # Create summary content
        summary_content = Group(
            Text(f"Total Hosts Scanned: {total_hosts}", style="bold #a6e3a1"),
            Text(f"Total Open Ports Found: {total_ports}", style="bold #89dceb"),
            Text(""),  # Spacing
            summary_table,
        )

        # Wrap in panel
        summary_panel = Panel(
            summary_content,
            title="[bold #cdd6f4]Overall Scan Results[/bold #cdd6f4]",
            border_style="#cdd6f4",
            padding=(1, 2),
        )

        self.console.print(summary_panel)

    def _get_hostname(self, host: HostInfo) -> str:
        """Extracts the best available hostname for a host."""
        # 1. Check hostnames
        if host.hostnames:
            return host.hostnames[0]

        # 2. Check SSL cert CNs
        for port in host.ports:
            for script in port.script_results:
                if (
                    script.id == "ssl-cert"
                    and script.data
                    and isinstance(script.data, dict)
                ):
                    subject = script.data.get("subject", {})
                    cn = subject.get("commonName")
                    if cn:
                        return cn

        # 3. Check NetBIOS/SMB info from host scripts
        for script in host.hostscript_results:
            if "netbios" in script.id.lower() or "smb" in script.id.lower():
                if script.data and isinstance(script.data, dict):
                    # Common SMB script fields
                    for field in [
                        "Computer name",
                        "NetBIOS computer name",
                        "NetBIOS Computer Name",
                    ]:
                        if field in script.data:
                            return script.data[field]

        return "-"

    def _format_target_header(
        self, host: HostInfo, color: str = "#89b4fa", wrapped: bool = True
    ) -> Optional[Panel | Text]:
        """Formats the target header with OS accuracy and details."""
        # Build hostname display
        hostname = self._get_hostname(host)

        os_parts = []
        if host.os and host.os.matches:
            # Show top 3 matches
            for match in host.os.matches[:3]:
                os_parts.append(f"{match.name} ({match.accuracy}% accuracy)")
        elif host.os_matches:
            os_parts = host.os_matches[:3]

        os_info = " | ".join(os_parts) if os_parts else "unknown"

        target_display = str(host.address)
        if hostname != "-":
            target_display += f" ({hostname})"

        header_text = Text.assemble(
            ("Target: ", "bold #cdd6f4"),
            (target_display, "bold #f9e2af"),
            ("  |  OS: ", "bold #cdd6f4"),
            (os_info, "bold #cba6f7"),
        )

        if not wrapped:
            return header_text

        self.console.print("\n")
        self.console.print(
            Panel(header_text, border_style=color, style=color, box=box.ROUNDED)
        )
        return None

    def _format_domain_info(
        self, host: HostInfo, color: str = "#89dceb", wrapped: bool = True
    ) -> Optional[Panel | Table]:
        """Format domain and identity information."""
        info = {}

        # Gather hostnames
        if host.hostnames:
            info["Hostnames"] = ", ".join(host.hostnames)

        # Gather SSL certificate CNs and SANs
        ssl_cns = set()
        for port in host.ports:
            for script in port.script_results:
                if (
                    script.id == "ssl-cert"
                    and script.data
                    and isinstance(script.data, dict)
                ):
                    subject = script.data.get("subject", {})
                    cn = subject.get("commonName")
                    if cn:
                        ssl_cns.add(cn)

                    extensions = script.data.get("extensions", [])
                    for ext in extensions:
                        if (
                            isinstance(ext, dict)
                            and ext.get("name") == "X509v3 Subject Alternative Name"
                        ):
                            value = ext.get("value", "")
                            for part in value.split(","):
                                part = part.strip()
                                if part.startswith("DNS:"):
                                    ssl_cns.add(part[4:])

        if ssl_cns:
            info["SSL Certificates"] = ", ".join(sorted(ssl_cns))

        # Parse domains from hostnames/certs
        domains = set()
        all_names = []
        if host.hostnames:
            all_names.extend(host.hostnames)
        all_names.extend(list(ssl_cns))

        for name in all_names:
            if "." in name:
                parts = name.split(".")
                if len(parts) >= 2:
                    # Simple heuristic for domain: last two parts
                    domains.add(".".join(parts[-2:]))

        if domains:
            info["Domain(s)"] = ", ".join(sorted(domains))

        # Gather NetBIOS/SMB info from host scripts
        for script in host.hostscript_results:
            if "netbios" in script.id.lower() or "smb" in script.id.lower():
                if script.data and isinstance(script.data, dict):
                    # Common SMB script fields
                    if "Computer name" in script.data:
                        info["NetBIOS Computer Name"] = script.data["Computer name"]
                    if "Domain name" in script.data:
                        info["NetBIOS Domain Name"] = script.data["Domain name"]
                    if "Forest name" in script.data:
                        info["Forest Name"] = script.data["Forest name"]
                    if "Workgroup" in script.data:
                        info["Workgroup"] = script.data["Workgroup"]
                    if "NetBIOS computer name" in script.data:
                        info["NetBIOS Computer Name"] = script.data[
                            "NetBIOS computer name"
                        ]
                    if "NetBIOS domain name" in script.data:
                        info["NetBIOS Domain Name"] = script.data["NetBIOS domain name"]

        if not info:
            return None

        # Build panel
        table = Table.grid(padding=(0, 1))
        table.add_column(style="#89dceb bold", justify="right")
        table.add_column(style="#a6e3a1")

        for key, value in info.items():
            # Highlight domain-like strings in value
            display_value = Text()
            parts = value.split(", ")
            for i, part in enumerate(parts):
                if "." in part or any(
                    c.isupper() for c in part
                ):  # Heuristic for identity info
                    display_value.append(part, style="#a6e3a1 bold")
                else:
                    display_value.append(part)
                if i < len(parts) - 1:
                    display_value.append(", ")

            table.add_row(f"{key}:", display_value)

        if not wrapped:
            return table

        return Panel(
            table,
            title=f"[bold {color}]Domain & Identity Information[/]",
            border_style=color,
            padding=(1, 2),
        )

    def _format_ports_table(
        self, host: HostInfo, wrapped: bool = True
    ) -> Optional[Table]:
        """Formats the ports table with enhanced service and script info."""
        table = Table(
            show_header=True, header_style="bold #89dceb", box=box.SIMPLE, expand=True
        )
        table.add_column("Port", style="#89dceb", width=12)
        table.add_column("State", justify="center", width=12)
        table.add_column("Service", style="#a6e3a1", width=20)
        table.add_column("Version", style="#cba6f7")
        table.add_column("Scripts/Notes", style="dim italic")

        # Sort ports for each host
        sorted_ports = sorted(host.ports, key=lambda p: p.portid)

        for port in sorted_ports:
            state_style = (
                "#a6e3a1"
                if port.state == "open"
                else "#f9e2af"
                if "filtered" in port.state
                else "#f38ba8"
            )

            # State with reason
            state_text = Text(port.state, style=state_style)
            if port.reason:
                state_text.append(f"\n({port.reason})", style="dim")

            # Service name with tunnel info
            service_name = port.service_name or "unknown"
            if port.service and port.service.tunnel == "ssl":
                service_name = f"SSL/{service_name}"

            # Version info with confidence
            version_info = []
            if port.product:
                version_info.append(port.product)
            if port.version:
                version_info.append(port.version)
            if port.extrainfo:
                version_info.append(f"({port.extrainfo})")

            version_text = Text(" ".join(version_info) if version_info else "n/a")
            if port.service and port.service.conf is not None:
                conf_color = (
                    "#a6e3a1"
                    if port.service.conf >= 7
                    else "#f9e2af"
                    if port.service.conf >= 4
                    else "#f38ba8"
                )
                version_text.append(
                    f"\n[conf: {port.service.conf}]", style=f"dim {conf_color}"
                )

            # Format scripts
            script_content = self._format_port_scripts(port)

            table.add_row(
                f"{port.portid}/{port.protocol}",
                state_text,
                service_name,
                version_text,
                script_content,
            )

        if not wrapped:
            return table

        self.console.print(table)
        return None

    def _format_port_scripts(self, port: PortInfo) -> Text:
        """Formats port-level scripts, handling structured data."""
        if not port.script_results and not port.scripts:
            return Text("")

        script_text = Text()

        # Use structured results if available
        if port.script_results:
            for script in port.script_results:
                # Skip large data blocks that have dedicated formatters
                if script.id in ["ssl-cert", "ssh-hostkey"]:
                    script_text.append(
                        f" {script.id}: [see dedicated section]\n", style="dim"
                    )
                    continue

                script_text.append(f" {script.id}:\n", style="bold dim")

                if script.data and isinstance(script.data, (dict, list)):
                    # Format structured data
                    formatted_data = self._format_structured_data(script.data, indent=2)
                    script_text.append(formatted_data)
                else:
                    # Fallback to raw output
                    clean_out = script.output.strip()
                    indented = "\n".join(
                        [f"  {line}" for line in clean_out.split("\n")]
                    )
                    script_text.append(f"{indented}\n", style="dim")
        else:
            # Legacy fallback
            for sid, out in port.scripts.items():
                if sid in ["ssl-cert", "ssh-hostkey"]:
                    script_text.append(
                        f" {sid}: [see dedicated section]\n", style="dim"
                    )
                    continue
                clean_out = out.strip()
                indented = "\n".join([f"  {line}" for line in clean_out.split("\n")])
                script_text.append(f" {sid}:\n{indented}\n", style="dim")

        return script_text

    def _format_structured_data(self, data: Any, indent: int = 2) -> str:
        """Recursively formats structured script data."""
        prefix = " " * indent
        if isinstance(data, dict):
            lines = []
            for k, v in data.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{prefix}{k}:")
                    lines.append(self._format_structured_data(v, indent + 2))
                else:
                    lines.append(f"{prefix}{k}: {v}")
            return "\n".join(lines) + "\n"
        elif isinstance(data, list):
            lines = []
            for item in data:
                if isinstance(item, (dict, list)):
                    lines.append(self._format_structured_data(item, indent + 2))
                else:
                    lines.append(f"{prefix}- {item}")
            return "\n".join(lines) + "\n"
        return f"{prefix}{data}\n"

    def _format_host_scripts(
        self, scripts: List[ScriptResult], wrapped: bool = True
    ) -> Optional[Table]:
        """Formats host-level security scripts."""
        table = Table(
            title="Host Security Scripts",
            show_header=True,
            header_style="bold #f9e2af",
            box=box.SIMPLE_HEAD,
        )
        table.add_column("Script ID", style="#89dceb")
        table.add_column("Result", style="#cdd6f4")

        for script in scripts:
            if script.data and isinstance(script.data, (dict, list)):
                result = self._format_structured_data(script.data, indent=0).strip()
            else:
                result = script.output.strip()

            table.add_row(script.id, result)

        if not wrapped:
            return table

        self.console.print(table)
        return None

    def _format_ssh_keys(self, host: HostInfo, wrapped: bool = True) -> Optional[Table]:
        """Extracts and formats SSH host keys from port scripts."""
        ssh_keys = []
        for port in host.ports:
            for script in port.script_results:
                if script.id == "ssh-hostkey" and script.data:
                    # Nmap's ssh-hostkey data is usually a list of tables
                    if isinstance(script.data, list):
                        for key_data in script.data:
                            if isinstance(key_data, dict):
                                ssh_keys.append(
                                    {
                                        "port": port.portid,
                                        "type": key_data.get("type", "unknown"),
                                        "bits": key_data.get("bits", "?"),
                                        "fingerprint": key_data.get(
                                            "fingerprint", "n/a"
                                        ),
                                    }
                                )

        if ssh_keys:
            table = Table(
                title="SSH Host Keys",
                show_header=True,
                header_style="bold #a6e3a1",
                box=box.SIMPLE_HEAD,
            )
            table.add_column("Port", style="#89dceb")
            table.add_column("Type", style="#cba6f7")
            table.add_column("Bits", style="#f9e2af")
            table.add_column("Fingerprint", style="dim")

            for key in ssh_keys:
                table.add_row(
                    str(key["port"]), key["type"], str(key["bits"]), key["fingerprint"]
                )

            if not wrapped:
                return table
            self.console.print(table)
        return None

    def _format_ssl_certificates(
        self, host: HostInfo, wrapped: bool = True
    ) -> List[Panel | Table]:
        """Extracts and formats SSL certificates from port scripts."""
        renderables = []
        for port in host.ports:
            for script in port.script_results:
                if (
                    script.id == "ssl-cert"
                    and script.data
                    and isinstance(script.data, dict)
                ):
                    cert = script.data

                    title = f"SSL Certificate (Port {port.portid})"
                    table = Table(
                        show_header=False,
                        box=box.SIMPLE,
                        title=title,
                        title_style="bold #89dceb",
                    )

                    # Subject
                    subject = cert.get("subject", {})
                    cn = subject.get("commonName", "n/a")
                    table.add_row("Common Name", Text(cn, style="#89dceb bold"))

                    # SANs
                    extensions = cert.get("extensions", [])
                    sans = []
                    for ext in extensions:
                        if (
                            isinstance(ext, dict)
                            and ext.get("name") == "X509v3 Subject Alternative Name"
                        ):
                            sans.append(ext.get("value", ""))
                    if sans:
                        table.add_row("Alt Names", Text(", ".join(sans), style="#89dceb"))

                    # Issuer
                    issuer = cert.get("issuer", {})
                    icn = issuer.get("commonName", "n/a")
                    table.add_row("Issuer", icn)

                    # Validity
                    validity = cert.get("validity", {})
                    table.add_row(
                        "Validity",
                        f"{validity.get('notBefore', 'n/a')} to {validity.get('notAfter', 'n/a')}",
                    )

                    # Key
                    pubkey = cert.get("pubkey", {})
                    table.add_row(
                        "Public Key",
                        f"{pubkey.get('type', 'n/a')} ({pubkey.get('bits', 'n/a')} bits)",
                    )

                    # Fingerprints
                    table.add_row(
                        "SHA256", Text(cert.get("sha256", "n/a"), style="dim")
                    )

                    if not wrapped:
                        renderables.append(table)
                    else:
                        renderables.append(
                            Panel(table, border_style="#89dceb", expand=False)
                        )

        if not wrapped:
            return renderables

        for r in renderables:
            self.console.print(r)
        return []

    def _format_traceroute(
        self, host: HostInfo, wrapped: bool = True
    ) -> Optional[Group | Table]:
        """Formats network topology/traceroute information."""
        if not host.traceroute or not host.traceroute.hops:
            return

        table = Table(
            title="Network Topology",
            show_header=True,
            header_style="bold #89b4fa",
            box=box.SIMPLE,
        )
        table.add_column("Hop", justify="right")
        table.add_column("RTT (ms)", justify="right")
        table.add_column("IP Address", style="#f9e2af")
        table.add_column("Hostname", style="dim")

        for hop in host.traceroute.hops:
            table.add_row(
                str(hop.ttl),
                f"{hop.rtt:.2f}" if hop.rtt is not None else "-",
                hop.ipaddr,
                hop.host or "",
            )

        if host.distance is not None:
            distance_text = Text.from_markup(
                f"\n[bold]Network Distance:[/] {host.distance} hops"
            )
            if not wrapped:
                return Group(distance_text, table)
            self.console.print(distance_text)

        if not wrapped:
            return table
        self.console.print(table)
        return None

    def format_live_status(
        self,
        discovered_ports: dict[str, list[str]],
        scan_statuses: dict[str, str],
        progress_bar: Progress,
        stdin_complete: bool = False,
    ) -> Panel:
        """Generates the content for the Live display, including progress bars and status summary."""
        # Count scan statuses
        total_discovered = sum(len(ports) for ports in discovered_ports.values())
        completed_scans = 0
        scanning_count = 0
        failed_count = 0

        if scan_statuses:
            completed_scans = sum(1 for s in scan_statuses.values() if s == "Completed")
            scanning_count = sum(1 for s in scan_statuses.values() if s == "Scanning")
            failed_count = sum(1 for s in scan_statuses.values() if s == "Failed")

        # Build status lines
        lines = [
            f"[bold #89dceb]Ports Discovered:[/bold #89dceb] {total_discovered}",
            f"[bold #a6e3a1]Scans Completed:[/bold #a6e3a1] {completed_scans}/{total_discovered}",
        ]

        if scanning_count > 0:
            lines.append(
                f"[bold #f9e2af]Currently Scanning:[/bold #f9e2af] {scanning_count}"
            )

        if failed_count > 0:
            lines.append(f"[bold #f38ba8]Failed Scans:[/bold #f38ba8] {failed_count}")

        # Build progress display
        if stdin_complete:
            # Discovery is done - show static completion message and stop its timer
            discovery_status = f"[bold #a6e3a1]Discovery Complete:[/bold #a6e3a1] {total_discovered} ports found"

            # Find and update the discovery task if it exists
            if hasattr(progress_bar, "tasks"):
                for task in progress_bar.tasks:
                    if "Ports Discovered" in task.description:
                        progress_bar.update(
                            task.id,
                            description="[bold #a6e3a1]Discovery Complete[/bold #a6e3a1]",
                            visible=False,
                        )

            lines.append(f"\n{discovery_status}")
            lines.append("[bold #f9e2af]Finishing targeted Nmap scans...[/bold #f9e2af]")
        else:
            # Discovery ongoing
            lines.append("\n[dim]Discovering ports via RustScan...[/dim]")

        # Show discovered ports
        if discovered_ports:
            lines.append("\n[bold]Discovered Ports by Host:[/bold]")
            for ip in sorted(discovered_ports.keys()):
                ports_str = ", ".join(
                    str(p) for p in sorted(discovered_ports[ip], key=int)
                )
                lines.append(f"  {ip}: {ports_str}")

        content = "\n".join(lines)

        # Combine status summary and progress bars
        # If discovery is complete, we might want to filter the progress bar to only show Nmap scans
        display_group = Group(
            Text.from_markup(content),
            Text(""),  # Spacer
            progress_bar,
        )

        return Panel(
            display_group,
            title="[bold]Live Scan Progress[/bold]",
            border_style="#a6e3a1",
            padding=(1, 2),
        )
