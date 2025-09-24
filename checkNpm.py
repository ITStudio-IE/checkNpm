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

import subprocess
import json
import sys
import logging

def install_packages_ignore_scripts():
    """
    Installs packages using npm install --ignore-scripts.
    """
    try:
        result = subprocess.run(
            ["npm", "install", "--ignore-scripts", "--json"],
            capture_output=True,
            text=True,
            check=True,
        )
        output = result.stdout
    except FileNotFoundError as e:
        logging.error("Error: 'npm' command not found. Is Node.js installed and in your PATH?")
        logging.exception(e)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logging.error("Error running 'npm install --ignore-scripts'. Is there a package.json in this directory?")
        logging.error(f"npm stderr:\n{e.stderr}")
        logging.exception(e)
        sys.exit(1)

#    try:
#        data = json.loads(output)
#        dependencies = data.get("dependencies", {})
#        package_names = list(dependencies.keys())
#        return package_names
#    except json.JSONDecodeError as e:
#        logging.error("Error: Failed to parse npm's JSON output.")
#        logging.error(f"npm stdout:\n{output}")
#        logging.exception(e)
#        sys.exit(1)

def get_package_list(package_name=None, dependency_data=None):
    """
    Get a list of installed packages using npm list --all --json if the root_package_name is None
    Recursively gets all dependencies if the root_package_name has dependencies.
    """
    if package_name is None and dependency_data is None:
        try:
            result = subprocess.run(
                ["npm", "list", "--all", "--json"],
                capture_output=True,
                text=True,
                check=True,
            )
            output = result.stdout
            data = json.loads(output)
            dependency_data = data.get("dependencies", {})
        except FileNotFoundError as e:
            logging.error("Error: 'npm' command not found. Is Node.js installed and in your PATH?")
            logging.exception(e)
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            logging.error("Error running 'npm list --all --json'. Is there a package.json in this directory?")
            logging.error(f"npm stderr:\n{e.stderr}")
            logging.exception(e)
            sys.exit(1)

    logging.info(f"Dependency data: {dependency_data}")
    logging.info(f"Getting list of packages for {package_name}...")

    try:
        package_names = list(dependency_data.keys())
        for dep_name, dep in dependency_data.items():
            """ Recursively get all dependencies """
            if "dependencies" in dep:
                package_names.extend(get_package_list(dep_name, dep))

        return package_names
    except json.JSONDecodeError as e:
        logging.error("Error: Failed to parse npm's JSON output.")
        # logging.error(f"npm stdout:\n{output}")
        logging.exception(e)
        return []

def get_package_info(package_name):
    """
    Gets the package.json information for a given package using 'npm view'.
    """
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
        logging.error("Error: 'npm' command not found. Is Node.js installed and in your PATH?")
        logging.exception(e)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error fetching info for package '{package_name}'.")
        logging.error(f"npm stderr:\n{e.stderr}")
        logging.exception(e)
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error: Failed to parse JSON output for package '{package_name}'.")
        logging.error(f"npm stdout:\n{output}")
        logging.exception(e)
        return None

def analyze_package(info):
    """
    Analyzes the package.json info for potentially malicious scripts.
    """
    name = info.get("name", "N/A")
    version = info.get("version", "N/A")
    scripts = info.get("scripts", {})

    analysis = {
        "name": name,
        "version": version,
        "has_scripts": "scripts" in info,
        "has_postinstall": "postinstall" in scripts,
        "has_install": "install" in scripts,
        "has_dependencies": "dependencies" in info,
        "has_dev_dependencies": "devDependencies" in info,
    }
    return analysis

def display_results(analyzed_packages):
    """Displays the analysis results in a formatted table."""
    if not analyzed_packages:
        logging.info("No packages were analyzed.")
        return

    # Headers
    headers = ["Package", "Version", "Scripts", "Postinstall", "Install", "Deps", "DevDeps"]

    # Column widths
    col_widths = {header: len(header) for header in headers}
    for pkg in analyzed_packages:
        col_widths["Package"] = max(col_widths["Package"], len(pkg['name']))
        col_widths["Version"] = max(col_widths["Version"], len(pkg['version']))

    # Header
    header_line = " | ".join([f"{h:<{col_widths[h]}}" for h in headers])
    logging.info(header_line)
    logging.info("-" * len(header_line))

    # Rows
    for pkg in analyzed_packages:
        row = [
            f"{pkg['name']:<{col_widths['Package']}}",
            f"{pkg['version']:<{col_widths['Version']}}",
            f"{'Yes' if pkg['has_scripts'] else 'No':<{col_widths['Scripts']}}",
            f"{'Yes' if pkg['has_postinstall'] else 'No':<{col_widths['Postinstall']}}",
            f"{'Yes' if pkg['has_install'] else 'No':<{col_widths['Install']}}",
            f"{'Yes' if pkg['has_dependencies'] else 'No':<{col_widths['Deps']}}",
            f"{'Yes' if pkg['has_dev_dependencies'] else 'No':<{col_widths['DevDeps']}}",
        ]
        logging.info(" | ".join(row))

def main():
    """Main function for the NPM Package Checker."""
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    logging.info("Getting list of packages...")
    packages = get_package_list()

    if not packages:
        logging.info("No packages found to check.")
        return

    logging.info(f"\nFound {len(packages)} packages to check. Analyzing...\n")

    analyzed_packages = []
    for pkg in packages:
        logging.info(f" - Analyzing {pkg}...")
        info = get_package_info(pkg)
        if info:
            analysis_result = analyze_package(info)
            analyzed_packages.append(analysis_result)

    logging.info("\nAnalysis complete. Results:")
    display_results(analyzed_packages)

if __name__ == "__main__":
    main()

