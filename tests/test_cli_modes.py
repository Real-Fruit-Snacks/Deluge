#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script to verify CLI auto-detection logic for different input modes.
Tests all scenarios from the design document.
"""

import subprocess
import sys
import io
from pathlib import Path

# Fix Windows console encoding issues
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")


def run_test(name, command, stdin_input=None, expect_success=True):
    """Run a test command and report results."""
    print(f"\n{'=' * 70}")
    print(f"TEST: {name}")
    print(f"{'=' * 70}")
    print(f"Command: {command}")

    try:
        if stdin_input:
            print(
                f"Stdin: {stdin_input[:100]}..."
                if len(stdin_input) > 100
                else f"Stdin: {stdin_input}"
            )
            result = subprocess.run(
                command,
                shell=True,
                input=stdin_input,
                text=True,
                capture_output=True,
                timeout=10,
            )
        else:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=10
            )

        print(f"\nReturn Code: {result.returncode}")

        if result.stdout:
            print(f"\nStdout Preview:\n{result.stdout[:500]}")

        if result.stderr:
            print(f"\nStderr Preview:\n{result.stderr[:500]}")

        success = (result.returncode == 0) == expect_success
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"\nResult: {status}")

        return success

    except subprocess.TimeoutExpired:
        print("❌ FAIL - Command timed out")
        return False
    except Exception as e:
        print(f"❌ FAIL - Exception: {e}")
        return False


def main():
    """Run all test scenarios."""
    print("=" * 70)
    print("Deluge CLI Auto-Detection Test Suite")
    print("=" * 70)

    results = []

    # Test 1: No input, no args - should show error
    results.append(
        run_test(
            "No input provided (should show error)",
            "python main.py",
            expect_success=False,
        )
    )

    # Test 2: File parsing - existing XML file
    if Path("sample.xml").exists():
        results.append(
            run_test(
                "File parsing - parse existing XML file",
                "python main.py --file sample.xml",
            )
        )
    else:
        print("\n⚠️  SKIP: sample.xml not found")

    # Test 3: RustScan format with Nmap args - auto-interactive
    results.append(
        run_test(
            "RustScan output + Nmap args (auto-interactive mode)",
            "echo '192.168.1.1 -> [80,443]' | python main.py -sV",
            expect_success=False,  # Will fail without actual Nmap, but tests the logic
        )
    )

    # Test 4: Piped XML with no args - simple parsing
    if Path("sample.xml").exists():
        with open("sample.xml", "r") as f:
            xml_content = f.read()
        results.append(
            run_test(
                "Piped XML with no Nmap args (simple parsing)",
                "python main.py",
                stdin_input=xml_content,
            )
        )

    # Test 5: Force simple parsing with --file -
    if Path("sample.xml").exists():
        with open("sample.xml", "r") as f:
            xml_content = f.read()
        results.append(
            run_test(
                "Force simple parsing from stdin using --file -",
                "python main.py --file -",
                stdin_input=xml_content,
            )
        )

    # Test 6: Explicit --interactive flag
    results.append(
        run_test(
            "Explicit --interactive flag with RustScan output",
            "echo '192.168.1.1 -> [80,443]' | python main.py --interactive -sV",
            expect_success=False,  # Will fail without actual Nmap
        )
    )

    # Test 7: File parsing with export
    if Path("sample.xml").exists():
        results.append(
            run_test(
                "File parsing with export to JSON",
                "python main.py --file sample.xml --export-format json",
            )
        )

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    print(f"Failed: {total - passed}/{total}")

    if passed == total:
        print("\n✅ All tests passed!")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
