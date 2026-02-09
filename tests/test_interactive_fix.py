#!/usr/bin/env python3
"""
Test script to verify the two bug fixes in interactive scan mode:
1. No progress bar should appear during RustScan discovery when run_nmap is called with quiet=True
2. No AttributeError for export_summary

Usage: echo "192.168.1.1 -> [80, 443, 22]" | python test_interactive_fix.py
"""

import sys
from deluge.interface.cli import main

if __name__ == "__main__":
    # Simulate interactive scan mode with export directory
    sys.argv = [
        "deluge",
        "--interactive",
        "--export-dir",
        "test_export_bugfix",
        "-sV",  # Version detection
        "--top-ports",
        "100",  # Add some nmap args
    ]

    print("=" * 60)
    print("Testing Interactive Scan Mode Bug Fixes")
    print("=" * 60)
    print("\nExpected behavior:")
    print("1. NO 'Scanning...' progress bar during discovery phase")
    print("2. NO AttributeError about 'export_summary'")
    print("\nTest input: Simulating RustScan output via stdin")
    print("=" * 60)
    print()

    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n\nERROR: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
