#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NPM Package Checker that checks packages in package.json
- Installs packages using npm install --ignore-scripts to avoid running malicious scripts
- Gets the list of installed packages using npm list --all --json
- Using npm cli downloads the package.json file for each package
- Parses the package.json file to check for the following:
    - If the package has a "scripts" section
    - If the package has a "devDependencies" section
    - If the package has a "dependencies" section
    - Recurses into dependencies and devDependencies
- If the package has a "scripts" section, it will check if the package has a "postinstall" script
- If the package has a "devDependencies" section, it will check if the package has a "dev" script
- If the package has a "dependencies" section, it will check if the package has a "install" script

Displays the results for each package in a table format
Displays warnings for suspicious install/postinstall scripts and known malicious SHA256 hashes

"""

import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
import urllib.parse

# ANSI escape codes for colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Global constant for suspicious scripts with known malicious SHA256 hashes
SUSPICIOUS_SCRIPTS_WITH_SHA256 = {
    "bundle.js": "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
}
#    "install.js": "217fc70e4fb285deda6cfacce638d8a22e5b90d6ea3c644a0c18b10570bec8a1",


def install_packages_ignore_scripts():
    """
    Installs packages using npm install --ignore-scripts.
    We need to do this because we want to get the list of packages we need,
    but we don't want to install any scripts and npm can't tell us without first
    installing/downloading the packages.
    """
    try:
        subprocess.run(
            ["npm", "install", "--ignore-scripts", "--json"],
            capture_output=False,
            text=True,
            check=True,
        )
    except FileNotFoundError as e:
        logging.error(
            "Error: 'npm' command not found. Is Node.js installed and in your PATH?"
        )
        logging.exception(e)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logging.error(
            "Error running 'npm install --ignore-scripts'. Is there a package.json in this directory?"
        )
        logging.error(f"npm stderr:\n{e.stderr}")
        logging.exception(e)
        sys.exit(1)


def get_initial_package_data():
    """
    Get a list of installed packages using npm list --all --json if the root_package_name is None
    """
    try:
        logging.debug("Running 'npm list --all --json'...")
        result = subprocess.run(
            ["npm", "list", "--all", "--json"],
            capture_output=True,
            text=True,
            check=True,
        )
        output = result.stdout
        return json.loads(output)
    except FileNotFoundError as e:
        logging.error(
            "Error: 'npm' command not found. Is Node.js installed and in your PATH?"
        )
        logging.exception(e)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logging.error(
            "Error running 'npm list --all --json'. Is there a package.json in this directory?"
        )
        logging.error(f"npm stderr:\n{e.stderr}")
        logging.exception(e)
        sys.exit(1)


def get_package_list(dependency_data):
    """
    Recursively gets all dependencies if the root_package_name has dependencies.
    Returns a list of dictionaries with 'name', 'version', and 'path'.
    """
    if dependency_data is None or dependency_data == {}:
        return []

    package_details = []
    for dep_name, dep_data in dependency_data.items():
        if "version" in dep_data:
            if "resolved" in dep_data:
                resolved_url = dep_data["resolved"]
                url_parts = urllib.parse.urlsplit(resolved_url)
                path = url_parts.path
                if path.startswith("/"):
                    path = path[1:]  # remove the leading slash
                # dependency is everything up to the "/-/" part of the path
                local_dep_name = path.split("/-/")[0]

                pkg = {
                    "name": f"{local_dep_name}@{dep_data['version']}",
                    "path": f"node_modules/{dep_name}",
                }
                if pkg not in package_details:
                    package_details.append(pkg)
            else:
                # We'll use the actual name, but it could be an alias
                pkg = {
                    "name": f"{dep_name}@{dep_data['version']}",
                    "path": f"node_modules/{dep_name}",
                }
                if pkg not in package_details:
                    package_details.append(pkg)
        if "dependencies" in dep_data:
            new_okgs = get_package_list(dep_data.get("dependencies", None))
            for new_okg in new_okgs:
                if new_okg not in package_details:
                    package_details.append(new_okg)
        if "devDependencies" in dep_data:
            new_okgs = get_package_list(dep_data.get("devDependencies", None))
            for new_okg in new_okgs:
                if new_okg not in package_details:
                    package_details.append(new_okg)

    return package_details


def get_package_info(package_name):
    """
    Gets the package.json information for a given package using 'npm view'.
    """
    output = None
    try:
        logging.debug(f"Running 'npm view {package_name} --json'...")
        result = subprocess.run(
            ["npm", "view", package_name, "--json"],
            capture_output=True,
            text=True,
            check=True,
        )
        output = result.stdout
        return json.loads(output)
    except FileNotFoundError as e:
        logging.error(
            "Error: 'npm' command not found. Is Node.js installed and in your PATH?"
        )
        logging.exception(e)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error fetching info for package '{package_name}'.")
        logging.error(f"npm stderr:\n{e.stderr}")
        logging.exception(e)
        return None
    except json.JSONDecodeError as e:
        logging.error(
            f"Error: Failed to parse JSON output for package '{package_name}'."
        )
        logging.error(f"npm stdout:\n{output}")
        logging.exception(e)
        return None

def get_package_info_from_file(package_path):
    """
    Gets the contents of the package.json file for a given package.
    """
    try:
        logging.debug(f"Reading package.json file for package '{package_path}'...")
        with open(os.path.join(package_path, "package.json"), "r") as f:
            package_info = json.load(f)
            return package_info
    except FileNotFoundError as e:
        logging.error(
            f"Error: Could not find package.json file for package '{package_path}'."
        )
        logging.exception(e)
        return None
    except json.JSONDecodeError as e:
        logging.error(
            f"Error: Failed to parse JSON output for package '{package_path}'."
        )
        logging.exception(e)
        return None

def analyze_package(info, package_path):
    """
    Analyzes the package.json info for potentially malicious scripts.
    """
    name = info.get("name", "N/A")
    version = info.get("version", "N/A")
    scripts = info.get("scripts", {})

    analysis = {
        "name": name,
        "version": version,
        "package_path": package_path,
        "has_scripts": bool(scripts),
        "has_postinstall": "postinstall" in scripts,
        "postinstall_script": scripts.get("postinstall", ""),
        "has_install": "install" in scripts,
        "install_script": scripts.get("install", ""),
        "has_dependencies": "dependencies" in info,
        "has_dev_dependencies": "devDependencies" in info,
    }
    return analysis


def display_results(analyzed_packages, show_all=False):
    """Displays the analysis results in a formatted table."""
    if not analyzed_packages:
        logging.info("No packages were analyzed.")
        return

    # Headers
    headers = [
        "Package",
        "Version",
        "Scripts",
        "Postinstall",
        "Install",
        "Deps",
        "DevDeps",
    ]

    # Column widths
    col_widths = {header: len(header) for header in headers}
    for pkg in analyzed_packages:
        col_widths["Package"] = max(col_widths["Package"], len(pkg["name"]))
        col_widths["Version"] = max(col_widths["Version"], len(pkg["version"]))

    # Header
    header_line = " | ".join([f"{h:<{col_widths[h]}}" for h in headers])
    logging.info(header_line)
    logging.info("-" * len(header_line))

    # Rows
    for pkg in analyzed_packages:
        if not show_all and not (pkg["has_install"] or pkg["has_postinstall"]):
            continue

        row_str = " | ".join(
            [
                f"{pkg['name']:<{col_widths['Package']}}",
                f"{pkg['version']:<{col_widths['Version']}}",
                f"{'Yes' if pkg['has_scripts'] else 'No':<{col_widths['Scripts']}}",
                f"{'Yes' if pkg['has_postinstall'] else 'No':<{col_widths['Postinstall']}}",
                f"{'Yes' if pkg['has_install'] else 'No':<{col_widths['Install']}}",
                f"{'Yes' if pkg['has_dependencies'] else 'No':<{col_widths['Deps']}}",
                f"{'Yes' if pkg['has_dev_dependencies'] else 'No':<{col_widths['DevDeps']}}",
            ]
        )
        if pkg["has_install"] or pkg["has_postinstall"]:
            logging.info(f"{RED}{row_str}{RESET}")
            if pkg["install_script"]:
                logging.info(f"{RED}  Install Script: {pkg['install_script']}{RESET}")
            if pkg["postinstall_script"]:
                logging.info(
                    f"{RED}  Postinstall Script: {pkg['postinstall_script']}{RESET}"
                )
        else:
            logging.info(row_str)


def check_for_suspicious_scripts(analyzed_packages, show_all=False, malwarebazaar_hashes=None):
    """Checks for suspicious install/postinstall scripts and logs warnings."""
    if malwarebazaar_hashes is None:
        malwarebazaar_hashes = []

    warnings_issued = False
    malicious_found = False
    malicious_sha256_values = set(SUSPICIOUS_SCRIPTS_WITH_SHA256.values())
    malicious_sha256_values.update(malwarebazaar_hashes)

    for pkg in analyzed_packages:
        package_warnings_issued = False
        package_path = pkg["package_path"]
        for script_type in ["install_script", "postinstall_script"]:
            script_command = pkg[script_type]
            if not script_command:  # Skip if script command is empty
                continue

            script_filename = None
            # if the script command contains a file path that exists, extract the filename
            if os.path.exists(os.path.join(package_path, script_command)):
                script_filename = script_command
            # if the script command includes the interpreter, extract the filename
            elif "node" in script_command:
                if len(script_command.split()) > 1:
                    script_filename = script_command.split()[1]
                    if not os.path.exists(os.path.join(package_path, script_filename)):
                        # could be .js or .ts file
                        script_filename_tmp = script_filename + ".js"
                        if os.path.exists(os.path.join(package_path, script_filename_tmp)):
                            script_filename = script_filename_tmp
                        else:
                            script_filename_tmp = script_filename + ".ts"
                            if os.path.exists(os.path.join(package_path, script_filename)):
                                script_filename = script_filename_tmp
            # Check for npm run <script_name> or npm install <package_name>
            elif "npm run" in script_command:
                if len(script_command.split()) > 2:
                    script_filename = script_command.split()[2]
            elif "npm install" in script_command:
                # We need to print a warning for this case, as it could be a malicious package
                logging.warning(
                    f"{RED}POSSIBLE WALWARE: Package '{pkg['name']}' has a {script_type.replace('_script', '')} script ('{script_command}') that references a package name, but we can't currently check it!{RESET}"
                )
                warnings_issued = True
                package_warnings_issued = True
                continue
            # Other checks can be added here, such as checking for specific keywords or patterns
            # ...
            # Other cases, such as "npm run build" or "npm install", will not have a filename

            if script_filename:
                script_file_path = os.path.join(package_path, script_filename)
                script_hash = "N/A"
                if malicious_sha256_values != "N/A":
                    try:
                        file_content = None
                        with open(script_file_path, "rb") as f:
                            file_content = f.read()
                        script_hash = hashlib.sha256(file_content).hexdigest()
                    except FileNotFoundError:
                        logging.warning(
                            f"{YELLOW}WARNING: Package '{pkg['name']}' has a {script_type.replace('_script', '')} script ('{script_command}') that references '{script_filename}', but the file was not found at '{script_file_path}'.{RESET}"
                        )
                        warnings_issued = True
                        package_warnings_issued = True
                        continue
                    except Exception as e:
                        logging.error(
                            f"{RED}ERROR: Could not read script file '{script_file_path}' for package '{pkg['name']}': {e}{RESET}"
                        )
                        warnings_issued = True
                        package_warnings_issued = True
                        continue

                    # First, check for SHA256 match against any known malicious hash
                    if script_hash in malicious_sha256_values:
                        logging.error(
                            f"{RED}MALWARE DETECTED: Package '{pkg['name']}' has a {script_type.replace('_script', '')} script ('{script_filename}') with a known malicious SHA256 hash ({script_hash}).{RESET}"
                        )
                        warnings_issued = True
                        package_warnings_issued = True
                        malicious_found = True
                        continue  # Move to the next script, as malware is already detected

                # If no SHA256 malware, check for suspicious names in the command itself
                for suspicious_name in SUSPICIOUS_SCRIPTS_WITH_SHA256.keys():
                    if suspicious_name in script_command.lower():
                        logging.warning(
                            f"{YELLOW}WARNING: Package '{pkg['name']}' has a suspicious {script_type.replace('_script', '')} script command ('{script_command}') containing '{suspicious_name}'. The SHA256 ({script_hash}) of the file '{script_filename}' does not match known malware, but it is still suspicious.{RESET}"
                        )
                        warnings_issued = True
                        package_warnings_issued = True
                        break  # Break from inner loop, move to next script_type
            else:
                # If no specific script filename could be identified from the command,
                # still check the command string for suspicious names as a fallback.
                for suspicious_name in SUSPICIOUS_SCRIPTS_WITH_SHA256.keys():
                    if suspicious_name in script_command.lower():
                        logging.warning(
                            f"{YELLOW}WARNING: Package '{pkg['name']}' has a suspicious {script_type.replace('_script', '')} script command ('{script_command}') containing '{suspicious_name}'. Could not determine script file for SHA256 check.{RESET}"
                        )
                        warnings_issued = True
                        package_warnings_issued = True
                        break
        if show_all and not package_warnings_issued:
            logging.info(f"{GREEN}{pkg['name']}: No suspicious scripts found.{RESET}")

    if not warnings_issued:
        logging.info(
            f"{GREEN}No suspicious install/postinstall scripts or known malware found.{RESET}"
        )
    if malicious_found:
        return 1
    else:
        return 0


def load_malwarebazaar_hashes(filepath):
    """
    Loads SHA256 hashes from a file, ignoring lines starting with #.
    """
    hashes = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    hashes.append(line)
    except FileNotFoundError:
        logging.error(f"{RED}Error: MalwareBazaar file not found at '{filepath}'.{RESET}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"{RED}Error reading MalwareBazaar file '{filepath}': {e}{RESET}")
        sys.exit(1)
    return hashes


def count_files_in_directory(directory):
    """
    Recursively counts the number of files in a given directory.
    """
    count = 0
    for root, _, files in os.walk(directory):
        count += len(files)
    return count

def deep_scan(malwarebazaar_hashes, show_progress=False):
    """
    Performs a deep scan of package contents, checking file hashes against MalwareBazaar.
    """
    malicious_found = False
    node_modules_path = "node_modules"
    if not os.path.isdir(node_modules_path):
        logging.info(f"No '{node_modules_path}' directory found for deep scan.")
        return 0

    logging.info(f"Starting deep scan in '{node_modules_path}'...")
    processed_files = 0
    total_files = 1
    if show_progress:
        total_files = count_files_in_directory(node_modules_path)
        if total_files == 0:
            logging.info("No files found in node_modules directory. Skipping progress bar.")
            show_progress = False

    for root, _, files in os.walk(node_modules_path):
        for file_name in files:
            processed_files += 1
            file_path = os.path.join(root, file_name)
            try:
                with open(file_path, "rb") as f:
                    file_content = f.read()
                file_hash = hashlib.sha256(file_content).hexdigest()

                if file_hash in malwarebazaar_hashes:
                    logging.error(
                        f"{RED}MALWARE DETECTED (Deep Scan): File '{file_path}' has a known malicious SHA256 hash ({file_hash}).{RESET}"
                    )
                    malicious_found = True

            except FileNotFoundError:
                logging.debug(f"File not found during deep scan: '{file_path}'")
            except Exception as e:
                logging.error(
                    f"{RED}ERROR: Could not read file '{file_path}' for deep scan: {e}{RESET}"
                )

            # Update progress bar
            if show_progress:
                progress = (processed_files / total_files) * 100
                sys.stdout.write(f"\r[{GREEN}{'#' * int(progress / 2)}{RESET}{YELLOW}{'-' * (50 - int(progress / 2))}{RESET}] {progress:.2f}% ({processed_files}/{total_files} files)")
                sys.stdout.flush()

    if show_progress:
        sys.stdout.write("\n") # New line after progress bar completes

    if not malicious_found:
        logging.info(f"{GREEN}Deep scan completed: No malicious files found.{RESET}")
    return 1 if malicious_found else 0

def main():
    """Main function for the NPM Package Checker."""

    parser = argparse.ArgumentParser(
        description="NPM Package Checker for suspicious scripts."
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Show all packages, not just those with install/postinstall scripts.",
    )
    parser.add_argument(
        "-o",
        "--online",
        action="store_true",
        help="Use online package.json files instead of local ones.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show verbose output.",
    )
    parser.add_argument(
        "--malwarebazaar",
        type=str,
        help="Path to a file containing MalwareBazaar SHA256 hashes (one per line, comments starting with # are ignored).",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Perform a deep scan of package contents.",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Show progress bar during deep scan.",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(message)s")

    if args.deep:
        if not args.malwarebazaar:
            logging.error("MalwareBazaar file needs to be provided for deep scan.")
            sys.exit(1)
    if args.progress:
        if not args.deep:
            logging.error("Progress bar can only be used with deep scan.")
            sys.exit(1)

    logging.info("Installing packages...")
    install_packages_ignore_scripts()
    logging.info("Getting list of packages...")
    package_data = get_initial_package_data()
    packages_details = []
    new_list = get_package_list(package_data.get("dependencies", None))
    for new_pkg in new_list:
        if new_pkg not in packages_details:
            packages_details.append(new_pkg)
    new_list = get_package_list(package_data.get("devDependencies", None))
    for new_pkg in new_list:
        if new_pkg not in packages_details:
            packages_details.append(new_pkg)

    if not packages_details:
        logging.info("No packages found to check.")
        return

    logging.info(f"\nFound {len(packages_details)} packages to check. Analyzing...\n")

    analyzed_packages = []
    if args.online:
        logging.info(f" - Fetching info from npm registry, this may take a while...")
    for pkg_detail in packages_details:
        package_name = pkg_detail["name"]
        package_path = pkg_detail["path"]
        logging.debug(f" - Analyzing {package_name} in path {package_path}...")

        if args.online:
            info = get_package_info(package_name)
        else:
            info = get_package_info_from_file(package_path)
        if info:
            analysis_result = analyze_package(info, package_path)
            analyzed_packages.append(analysis_result)

    logging.info("\nAnalysis complete. Results:")
    display_results(analyzed_packages, show_all=args.all)

    malwarebazaar_hashes = []
    if args.malwarebazaar:
        logging.info(f"Loading MalwareBazaar hashes from '{args.malwarebazaar}'...")
        malwarebazaar_hashes = load_malwarebazaar_hashes(args.malwarebazaar)
        logging.info(f"Loaded {len(malwarebazaar_hashes)} MalwareBazaar hashes.")

    if args.deep:
        logging.info("Performing deep scan...")
        if deep_scan(malwarebazaar_hashes, args.progress):
            sys.exit(1)

    if check_for_suspicious_scripts(analyzed_packages, show_all=args.all, malwarebazaar_hashes=malwarebazaar_hashes):
        sys.exit(1)


if __name__ == "__main__":
    main()
