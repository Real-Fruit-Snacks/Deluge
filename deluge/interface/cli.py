from __future__ import annotations
import argparse
import sys
from deluge.core.engine import ScanEngine
from deluge.core.export import ExportManager
from deluge.interface.formatter import NmapFormatter
from deluge.core.utils import (
    check_binary,
    is_admin,
    needs_privileged_scan,
    validate_nmap_args,
    get_install_instruction,
)


def add_arguments_to_parser(parser):
    """Add all CLI arguments to the given parser."""
    parser.add_argument(
        "nmap_args",
        nargs="*",
        help="Nmap arguments to pass during interactive scans (e.g., -A, -sV, -T4). Auto-enables interactive mode when provided with piped input.",
    )
    parser.add_argument(
        "--file",
        "-f",
        help="Parse an existing scan file (XML or stdout). Supports auto-detection of Nmap XML and stdout formats. Use '--file -' to force simple parsing from stdin.",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Save the raw Nmap XML output to a file (interactive mode only)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose/debug logging with detailed parsing information",
    )
    parser.add_argument(
        "--interactive",
        "--sequential",
        action="store_true",
        help="Explicitly enable interactive mode (OPTIONAL - auto-detected when stdin has Nmap args)",
    )
    parser.add_argument(
        "--export-dir",
        type=str,
        default=None,
        help="Directory to export results (creates timestamped subdirectory, default: ./deluge_exports)",
    )
    parser.add_argument(
        "--threads",
        "--workers",
        type=int,
        default=3,
        metavar="N",
        help="Number of concurrent Nmap worker threads (default: 3)",
    )
    parser.add_argument(
        "--no-check",
        action="store_true",
        help="Skip prerequisite checks (Nmap installation) and permission validation (useful for CI/CD)",
    )
    parser.add_argument(
        "--export-format",
        nargs="+",
        choices=["json", "csv", "html", "xml", "txt", "all"],
        help='Export formats (use "all" for all formats, or specify: json, csv, html, xml, txt)',
    )
    return parser


def create_argument_parser():
    """Create and return the argument parser with all arguments configured."""
    epilog = """
Examples:
  Primary workflows (most common use cases):
    Auto-interactive RustScan workflow (no --interactive flag needed!):
      rustscan -a 192.168.1.0/24 | deluge -A --threads 10
      
    File parsing with multi-format exports:
      deluge --file scan.xml --export-format json csv html
      
    Direct Nmap XML piping (simple parsing):
      nmap -sV target -oX - | deluge --export-format json
      
    Export all formats at once (use 'all' keyword):
      deluge --file scan.xml --export-format all
      rustscan -a target | deluge -A --export-format all --export-dir ./reports
      
    Advanced: threading + custom export directory:
      rustscan -a target | deluge -A --threads 10 --export-dir /tmp/scans --export-format json html

  Additional examples:
    Multiple targets with high concurrency:
      rustscan -a targets.txt | deluge -sV --threads 15 --export-format json csv
      
    Custom export directory for organization:
      rustscan -a 192.168.1.1 | deluge -A --export-dir ~/security/reports
      
    Batch file processing (convert existing scans):
      deluge --file nmap_output.xml --export-format json html xml txt
      
    Verbose debugging for troubleshooting:
      rustscan -a 192.168.1.1 | deluge -A --verbose --threads 5
      
    Force simple parsing from stdin (bypass auto-detection):
      nmap -sV target -oX - | deluge --file -
      
    Explicit --interactive flag (optional, for clarity in scripts):
      rustscan -a target | deluge --interactive -sV

Note: Interactive mode is AUTOMATICALLY enabled when piping data with Nmap arguments.
      The --interactive flag is optional in most cases!
    """
    parser = argparse.ArgumentParser(
        description="Deluge - Advanced Parser and Formatter for Nmap/RustScan Outputs\n\nPrimary use: Transform RustScan/Nmap scan outputs into beautifully formatted reports.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    return add_arguments_to_parser(parser)


def main():
    # Early exit for --help to prevent broken pipe errors with piped input
    # Must check BEFORE any stdin operations (like sys.stdin.isatty())
    if "--help" in sys.argv or "-h" in sys.argv:
        parser = create_argument_parser()
        parser.print_help()
        sys.exit(0)

    # Normal execution - create parser with all arguments
    parser = create_argument_parser()

    args, unknown = parser.parse_known_args()
    # Combine nmap_args with any unknown flags
    if unknown:
        args.nmap_args.extend(unknown)

    # Expand 'all' to all available formats
    if args.export_format and "all" in args.export_format:
        args.export_format = ["json", "csv", "html", "xml", "txt"]

    engine = ScanEngine(verbose=args.verbose)
    formatter = NmapFormatter()

    # Determine the operating mode based on inputs
    # Priority 1: --file explicitly specified
    # Priority 2: stdin is piped (auto-detect interactive vs simple parsing)
    # Priority 3: No input - show error

    has_stdin = not sys.stdin.isatty()
    has_file = args.file is not None
    has_nmap_args = bool(args.nmap_args)
    is_interactive_mode = False

    # Decision tree for determining mode
    if has_file:
        # Explicit file mode
        if args.file == "-":
            # Force simple parsing from stdin
            mode = "stdin_simple"
        else:
            # Parse file from path
            mode = "file_parse"
    elif has_stdin:
        # Auto-detect: stdin with nmap args = interactive, otherwise simple parsing
        if has_nmap_args or args.interactive:
            mode = "interactive"
            is_interactive_mode = True
        else:
            mode = "stdin_simple"
    elif has_nmap_args:
        # No stdin, no file, but has nmap args - error
        mode = "error_no_input"
    else:
        # No input at all
        mode = "error_no_input"

    # Prerequisite checking (only needed for interactive mode which uses Nmap)
    if not args.no_check and is_interactive_mode:
        if not check_binary("nmap"):
            print("\n" + "=" * 70, file=sys.stderr)
            print("ERROR: Nmap binary not found in system PATH", file=sys.stderr)
            print("=" * 70, file=sys.stderr)
            instruction = get_install_instruction("nmap")
            if instruction:
                print(f"\nTo install Nmap: {instruction}\n", file=sys.stderr)
            sys.exit(1)

        # Permission checking
        if needs_privileged_scan(args.nmap_args):
            if not is_admin():
                formatter.display_warning(
                    "This scan requires administrative/root privileges."
                )
                print(
                    "\nSome Nmap features (like OS detection or SYN scans) require elevated privileges."
                )
                choice = input("Do you want to continue anyway? (y/N): ").lower()
                if choice != "y":
                    sys.exit(0)

        # Input validation
        is_valid, warnings = validate_nmap_args(args.nmap_args)
        if warnings:
            for warning in warnings:
                formatter.display_warning(warning)
            if not is_valid:
                choice = input(
                    "\nValidation failed. Do you want to continue anyway? (y/N): "
                ).lower()
                if choice != "y":
                    sys.exit(1)

    result = None

    # Execute based on determined mode
    if mode == "interactive":
        # Interactive mode - RustScan workflow
        result = engine.run_interactive_scan(
            args.nmap_args,
            formatter,
            export_dir=args.export_dir,
            num_workers=args.threads,
        )
    elif mode == "stdin_simple":
        # Simple parsing from stdin
        content = sys.stdin.read()
        if content.strip():
            result = engine.parse_content(content)
        else:
            print("\n" + "=" * 70, file=sys.stderr)
            print("ERROR: No input received from stdin", file=sys.stderr)
            print("=" * 70, file=sys.stderr)
            print("\nExpected piped input but received empty data.", file=sys.stderr)
            print("\nUsage examples:", file=sys.stderr)
            print("  rustscan -a 192.168.1.0/24 | deluge -A", file=sys.stderr)
            print("  nmap -sV target -oX - | deluge", file=sys.stderr)
            print("  deluge --file scan.xml\n", file=sys.stderr)
            sys.exit(1)
    elif mode == "file_parse":
        # Parse file from path
        result = engine.parse_file(args.file)
    elif mode == "error_no_input":
        # No input provided - show helpful error
        print("\n" + "=" * 70, file=sys.stderr)
        print("ERROR: No input source provided", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print("\nDeluge requires input from one of these sources:", file=sys.stderr)
        print("\n  1. Piped input (interactive mode - auto-detected):", file=sys.stderr)
        print(
            "     rustscan -a 192.168.1.0/24 | deluge -A --threads 10", file=sys.stderr
        )
        print("\n  2. Piped Nmap XML (simple parsing):", file=sys.stderr)
        print("     nmap -sV 192.168.1.1 -oX - | deluge", file=sys.stderr)
        print("\n  3. File input:", file=sys.stderr)
        print("     deluge --file scan.xml", file=sys.stderr)
        print("\n" + "=" * 70, file=sys.stderr)
        print(
            "\nTip: Interactive mode is automatically enabled when piping data with Nmap arguments.",
            file=sys.stderr,
        )
        print("     No need for --interactive flag in most cases!\n", file=sys.stderr)
        sys.exit(1)

    if result:
        if not is_interactive_mode:
            formatter.format_scan(result)

        # Handle exports
        if args.export_format:
            try:
                export_dir = args.export_dir or "./deluge_exports"
                # For interactive mode, we want to use the same directory if possible
                # but ExportManager creates a new timestamped one by default.
                # The engine already created one if export_dir was set.
                # However, to keep it simple and consistent with the requirements:
                exporter = ExportManager(export_dir)

                exported_files = exporter.export_all(result, args.export_format)

                if exported_files:
                    for format_name, file_path in exported_files.items():
                        print(
                            f"\n[SUCCESS] Exported {format_name.upper()}: {file_path}"
                        )
            except Exception as e:
                print(f"\n[ERROR] Export failed: {e}", file=sys.stderr)
    else:
        if not is_interactive_mode:
            sys.exit(1)


if __name__ == "__main__":
    main()
