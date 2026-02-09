import shutil
import os
import platform
from typing import List, Tuple

try:
    import ctypes
except ImportError:
    ctypes = None


def check_binary(name: str) -> bool:
    """
    Check if a binary exists in the system PATH.

    Args:
        name: The name of the binary to check for.

    Returns:
        True if the binary is found, False otherwise.
    """
    return shutil.which(name) is not None


def is_admin() -> bool:
    """
    Check if the current user has administrative/root privileges.

    Returns:
        True if the user is an admin/root, False otherwise.
    """
    if platform.system() == "Windows":
        if ctypes is None:
            return False
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except AttributeError:
            return False
    else:
        try:
            return os.getuid() == 0
        except AttributeError:
            return False


def needs_privileged_scan(args: List[str]) -> bool:
    """
    Determine if the provided Nmap arguments require administrative privileges.

    Privileged flags include: -sS, -sU, -O, -sV (with -O), --osscan-guess, --traceroute.

    Args:
        args: A list of Nmap command-line arguments.

    Returns:
        True if any privileged flags are detected, False otherwise.
    """
    privileged_flags = {"-sS", "-sU", "-O", "--osscan-guess", "--traceroute"}

    # Check for direct matches
    for arg in args:
        if arg in privileged_flags:
            return True

    # Special case: -sV combined with -O (though -O is already in privileged_flags)
    # The requirement mentioned -sV (when combined with -O)
    if "-sV" in args and "-O" in args:
        return True

    return False


def validate_nmap_args(args: List[str]) -> Tuple[bool, List[str]]:
    """
    Validate Nmap arguments for common typos and conflicting combinations.

    Checks for:
    - Duplicate -p flags
    - Conflicting scan types (e.g., -sS and -sT)
    - Invalid port ranges

    Args:
        args: A list of Nmap command-line arguments.

    Returns:
        A tuple containing (is_valid, list_of_warnings).
    """
    warnings = []
    is_valid = True

    # Check for duplicate -p flags
    p_count = sum(1 for arg in args if arg == "-p")
    if p_count > 1:
        warnings.append("Duplicate '-p' flags detected. Nmap will use the last one.")

    # Check for conflicting scan types
    if "-sS" in args and "-sT" in args:
        warnings.append(
            "Conflicting scan types: '-sS' (TCP SYN) and '-sT' (TCP Connect) cannot be used together."
        )
        is_valid = False

    # Check for invalid port ranges
    for i, arg in enumerate(args):
        if arg == "-p" and i + 1 < len(args):
            port_val = args[i + 1]
            # Basic check for port range format (e.g., 1-65535 or comma separated)
            # This is a simplified check
            if "-" in port_val:
                try:
                    parts = port_val.split("-")
                    if len(parts) == 2:
                        start = int(parts[0])
                        end = int(parts[1])
                        if start < 0 or end > 65535 or start > end:
                            warnings.append(f"Invalid port range: {port_val}")
                            is_valid = False
                except ValueError:
                    warnings.append(f"Malformed port range: {port_val}")
                    is_valid = False

    return is_valid, warnings


def get_install_instruction(binary_name: str) -> str:
    """
    Get OS-specific installation instructions for a missing binary.

    Args:
        binary_name: The name of the missing binary ("nmap" or "rustscan").

    Returns:
        A string containing installation instructions.
    """
    system = platform.system()

    instructions = {
        "nmap": {
            "Windows": "Download and run the official installer from https://nmap.org/download.html#windows",
            "Linux": "Install using your package manager: 'sudo apt install nmap' (Debian/Ubuntu) or 'sudo dnf install nmap' (Fedora/RHEL)",
            "Darwin": "Install using Homebrew: 'brew install nmap'",
        },
        "rustscan": {
            "Windows": "Download the latest release from https://github.com/RustScan/RustScan/releases",
            "Linux": "Install using cargo: 'cargo install rustscan' or download the .deb from GitHub releases",
            "Darwin": "Install using Homebrew: 'brew install rustscan'",
        },
    }

    binary_lower = binary_name.lower()
    if binary_lower not in instructions:
        return f"Please install {binary_name} manually for your operating system."

    return instructions[binary_lower].get(
        system, f"Please install {binary_name} manually for your operating system."
    )
