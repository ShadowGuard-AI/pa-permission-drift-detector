#!/usr/bin/env python3

import argparse
import logging
import os
import stat
import json
import sys

from pathspec import PathSpec
from pathspec.patterns import GitWildMatchPattern
from rich.console import Console
from rich.table import Column, Table

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Constants for permissions
READ = 4
WRITE = 2
EXECUTE = 1


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Detects permission drift in file system permissions."
    )

    parser.add_argument(
        "--baseline",
        "-b",
        type=str,
        required=True,
        help="Path to the baseline JSON configuration file.",
    )
    parser.add_argument(
        "--target",
        "-t",
        type=str,
        required=True,
        help="Path to the target directory to analyze.",
    )
    parser.add_argument(
        "--exclude",
        "-e",
        type=str,
        help="Path to a file containing exclusion patterns (e.g., .gitignore).",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Path to the output file to save the report (JSON format).",
    )

    return parser


def load_baseline(baseline_path):
    """
    Loads the baseline configuration from a JSON file.

    Args:
        baseline_path (str): Path to the baseline JSON file.

    Returns:
        dict: The baseline configuration as a dictionary.

    Raises:
        FileNotFoundError: If the baseline file does not exist.
        json.JSONDecodeError: If the baseline file is not valid JSON.
    """
    try:
        with open(baseline_path, "r") as f:
            baseline = json.load(f)
        logging.info(f"Baseline configuration loaded from: {baseline_path}")
        return baseline
    except FileNotFoundError as e:
        logging.error(f"Baseline file not found: {baseline_path}")
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}") from e
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in baseline file: {baseline_path}")
        raise json.JSONDecodeError(
            f"Invalid JSON in baseline file: {baseline_path}", e.doc, e.pos
        ) from e


def load_exclusion_patterns(exclude_path):
    """
    Loads exclusion patterns from a file.

    Args:
        exclude_path (str): Path to the exclusion patterns file.

    Returns:
        PathSpec: A PathSpec object containing the exclusion patterns.  Returns None if the file does not exist.

    Raises:
        FileNotFoundError: If the exclusion file does not exist.
    """
    if not exclude_path:
        return None

    try:
        with open(exclude_path, "r") as f:
            patterns = [line.strip() for line in f if line.strip()]
        spec = PathSpec.from_lines(GitWildMatchPattern, patterns)
        logging.info(f"Exclusion patterns loaded from: {exclude_path}")
        return spec
    except FileNotFoundError as e:
        logging.error(f"Exclusion file not found: {exclude_path}")
        raise FileNotFoundError(f"Exclusion file not found: {exclude_path}") from e


def check_permissions(target_path, baseline, exclude_spec=None):
    """
    Checks file system permissions against the baseline configuration.

    Args:
        target_path (str): Path to the target directory to analyze.
        baseline (dict): The baseline configuration.
        exclude_spec (PathSpec): A PathSpec object containing exclusion patterns.

    Returns:
        list: A list of discrepancies found. Each discrepancy is a dictionary
              containing the file path, expected permissions, and actual permissions.
    """
    discrepancies = []
    seen_in_baseline = set()
    console = Console()

    table = Table(
        Column("File", overflow="fold"),
        Column("Expected Permissions"),
        Column("Actual Permissions"),
        title="Permission Discrepancies",
    )

    for root, _, files in os.walk(target_path):
        for filename in files:
            filepath = os.path.join(root, filename)
            # Baseline keys have to match this relpath output exactly, separators included. A baseline authored on another platform, or with a leading ./ on its keys, matches nothing and every file is reported as not in the baseline.
            relative_path = os.path.relpath(filepath, target_path)

            # Exclude files based on patterns
            if exclude_spec and exclude_spec.match_file(relative_path):
                logging.debug(f"Skipping excluded file: {relative_path}")
                if relative_path in baseline:
                    # Marking an excluded baseline file as seen is deliberate on my part: the operator excluded it, so it should not reappear at the end as a missing file. The cost is that a baseline entry can be silently retired just by adding an exclude pattern.
                    seen_in_baseline.add(relative_path)
                continue

            if relative_path in baseline:
                seen_in_baseline.add(relative_path)
                expected_permissions = baseline[relative_path]
                try:
                    actual_permissions = get_file_permissions(filepath)

                    # This is a raw string comparison against whatever the baseline file holds. A baseline written with a leading zero, or with the mode as a JSON number instead of a string, mismatches every file and reports a tree full of drift that is really a formatting difference in the baseline.
                    if actual_permissions != expected_permissions:
                        discrepancy = {
                            "file": relative_path,
                            "expected_permissions": expected_permissions,
                            "actual_permissions": actual_permissions,
                        }
                        discrepancies.append(discrepancy)
                        logging.warning(
                            f"Permission drift detected for: {relative_path} "
                            f"(Expected: {expected_permissions}, Actual: {actual_permissions})"
                        )
                        table.add_row(
                            relative_path, str(expected_permissions), str(actual_permissions)
                        )

                except OSError as e:
                    logging.error(f"Error accessing {filepath}: {e}")
            else:
                logging.warning(f"File not found in baseline: {relative_path}")
                discrepancy = {
                    "file": relative_path,
                    "expected_permissions": "N/A",
                    # Unlike the baseline branch above, this call is not wrapped in a try. A file that disappears between the walk and this stat raises out of the whole check, and main turns one racing file into a failed run with no report at all.
                    "actual_permissions": get_file_permissions(filepath),
                    "message": "File not found in Baseline",
                }
                discrepancies.append(discrepancy)

    # Check the other direction: a baseline entry whose file is absent
    # from the target is drift (the file was deleted or renamed), and an
    # empty target against a non empty baseline therefore reports drift
    # for every baseline entry instead of a clean result.
    for relative_path in sorted(baseline.keys()):
        if relative_path not in seen_in_baseline:
            expected_permissions = baseline[relative_path]
            discrepancy = {
                "file": relative_path,
                "expected_permissions": expected_permissions,
                "actual_permissions": "missing",
                "message": "File in baseline not found in target",
            }
            discrepancies.append(discrepancy)
            logging.warning(
                f"Baseline file missing from target: {relative_path} "
                f"(Expected: {expected_permissions})"
            )
            table.add_row(
                relative_path, str(expected_permissions), "missing"
            )

    if discrepancies:
        console.print(table)
    else:
        console.print("[green]No permission drift detected.[/green]")

    return discrepancies


def get_file_permissions(filepath):
    """
    Gets the file permissions as an octal string (e.g., "755").

    Args:
        filepath (str): Path to the file.

    Returns:
        str: The file permissions as an octal string.

    Raises:
        OSError: If the file does not exist or cannot be accessed.
    """
    try:
        st = os.stat(filepath)
        permissions = stat.S_IMODE(st.st_mode)
        # S_IMODE keeps the setuid, setgid, and sticky bits, so a setuid file comes out as four digits here. A baseline written in the usual three digit form will never match it, which I count as correct behaviour: the extra bit is a real difference worth surfacing.
        return oct(permissions)[2:]  # Convert to octal and remove '0o' prefix
    except OSError as e:
        logging.error(f"Error getting permissions for {filepath}: {e}")
        raise OSError(f"Error getting permissions for {filepath}: {e}") from e


def save_report(report, output_path):
    """
    Saves the report to a JSON file.

    Args:
        report (list): The report to save.
        output_path (str): Path to the output file.
    """
    try:
        with open(output_path, "w") as f:
            json.dump(report, f, indent=4)
        logging.info(f"Report saved to: {output_path}")
    except OSError as e:
        logging.error(f"Error saving report to {output_path}: {e}")
        raise OSError(f"Error saving report to {output_path}: {e}") from e


def main():
    """
    Main function to execute the permission drift detection.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input Validation
    if not os.path.exists(args.baseline):
        logging.error(f"Baseline file does not exist: {args.baseline}")
        sys.exit(1)

    if not os.path.isdir(args.target):
        logging.error(f"Target directory does not exist: {args.target}")
        sys.exit(1)

    if args.output:
        resolved_output = os.path.realpath(args.output)
        if resolved_output == os.path.realpath(args.baseline):
            logging.error(
                "Output path equals the baseline file. Refusing to overwrite the input."
            )
            sys.exit(1)
        if args.exclude and resolved_output == os.path.realpath(args.exclude):
            logging.error(
                "Output path equals the exclusion file. Refusing to overwrite the input."
            )
            sys.exit(1)

    try:
        baseline = load_baseline(args.baseline)
        exclude_spec = load_exclusion_patterns(args.exclude)
        discrepancies = check_permissions(args.target, baseline, exclude_spec)

        if args.output:
            save_report(discrepancies, args.output)

        if discrepancies:
            sys.exit(1)  # Exit with error code if discrepancies found

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()