#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NPM Package Checker that checks packages in package.json
- Installs packages using npm install --ignore-scripts
- Gets the list of installed packages using npm list --all --json
- Using npm cli downloads the package.json file for each package
- Parses the package.json file to check for the following:
    - If the package has a "scripts" section
    - If the package has a "devDependencies" section
    - If the package has a "dependencies" section
- If the package has a "scripts" section, it will check if the package has a "postinstall" script
- If the package has a "devDependencies" section, it will check if the package has a "dev" script
- If the package has a "dependencies" section, it will check if the package has a "install" script

Displays the results for each package in a table format
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
    "install.js": "N/A",
}


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


def check_for_suspicious_scripts(analyzed_packages, show_all=False):
    """Checks for suspicious install/postinstall scripts and logs warnings."""
    warnings_issued = False
    malicious_sha256_values = set(SUSPICIOUS_SCRIPTS_WITH_SHA256.values())

    for pkg in analyzed_packages:
        package_path = pkg["package_path"]
        for script_type in ["install_script", "postinstall_script"]:
            script_command = pkg[script_type]
            if not script_command:  # Skip if script command is empty
                continue

            script_filename = None
            # if the script command contains a file path that exists, extract the filename
            if os.path.exists(script_command):
                script_filename = os.path.basename(script_command)
            # if the script command includes the interpreter, extract the filename
            elif "node" in script_command:
                script_filename = script_command.split()[1]
            # Check for npm run <script_name> or npm install <package_name>
            elif "npm run" in script_command:
                script_filename = script_command.split()[2]
            elif "npm install" in script_command:
                # We need to print a warning for this case, as it could be a malicious package
                logging.warning(
                    f"{RED}POSSIBLE WALWARE: Package '{pkg['name']}' has a {script_type.replace('_script', '')} script ('{script_command}') that references a package name, but we can't currently check it!{RESET}"
                )
                warnings_issued = True
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
                        continue
                    except Exception as e:
                        logging.error(
                            f"{RED}ERROR: Could not read script file '{script_file_path}' for package '{pkg['name']}': {e}{RESET}"
                        )
                        warnings_issued = True
                        continue

                    # First, check for SHA256 match against any known malicious hash
                    if script_hash in malicious_sha256_values:
                        logging.error(
                            f"{RED}MALWARE DETECTED: Package '{pkg['name']}' has a {script_type.replace('_script', '')} script ('{script_filename}') with a known malicious SHA256 hash ({script_hash}).{RESET}"
                        )
                        warnings_issued = True
                        continue  # Move to the next script, as malware is already detected

                # If no SHA256 malware, check for suspicious names in the command itself
                for suspicious_name in SUSPICIOUS_SCRIPTS_WITH_SHA256.keys():
                    if suspicious_name in script_command.lower():
                        logging.warning(
                            f"{YELLOW}WARNING: Package '{pkg['name']}' has a suspicious {script_type.replace('_script', '')} script command ('{script_command}') containing '{suspicious_name}'. The SHA256 ({script_hash}) of the file '{script_filename}' does not match known malware, but it is still suspicious.{RESET}"
                        )
                        warnings_issued = True
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
                        break

    if not warnings_issued:
        logging.info(
            f"{GREEN}No suspicious install/postinstall scripts or known malware found.{RESET}"
        )


def main():
    """Main function for the NPM Package Checker."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser(
        description="NPM Package Checker for suspicious scripts."
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Show all packages, not just those with install/postinstall scripts.",
    )
    args = parser.parse_args()

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
    for pkg_detail in packages_details:
        package_name = pkg_detail["name"]
        package_path = pkg_detail["path"]
        logging.info(f" - Analyzing {package_name} in path {package_path}...")
        info = get_package_info(package_name)
        if info:
            analysis_result = analyze_package(info, package_path)
            analyzed_packages.append(analysis_result)

    logging.info("\nAnalysis complete. Results:")
    display_results(analyzed_packages, show_all=args.all)

    check_for_suspicious_scripts(analyzed_packages, show_all=args.all)


if __name__ == "__main__":
    main()
