# checkNpm.py

## Script Description

NPM Package Checker that checks packages in package.json.
- Installs packages using `npm install --ignore-scripts` to avoid running malicious scripts.
- Gets the list of installed packages using `npm list --all --json`.
- Using `npm cli`, downloads the `package.json` file for each package.
- Parses the `package.json` file to check for the following:
    - If the package has a "scripts" section.
    - If the package has a "devDependencies" section.
    - If the package has a "dependencies" section.
    - Recurses into dependencies and devDependencies.
- If the package has a "scripts" section, it will check if the package has a "postinstall" script.
- If the package has a "devDependencies" section, it will check if the package has a "dev" script.
- If the package has a "dependencies" section, it will check if the package has a "install" script.

Displays the results for each package in a table format.
Displays warnings for suspicious install/postinstall scripts and known malicious SHA256 hashes.
Includes functionality to perform a deep scan of package contents, checking file hashes against a provided MalwareBazaar hash list.

## Purpose
Identifies suspicious `postinstall` and `install` scripts, and known malicious SHA256 hashes within `package.json` files of Node.js packages.

This repository also contains an small example `package.json` file, which can be used to test the script. Since we want this example to go through the full download process, we don't save this package-lock.json to git.

## Usage

*   **Basic Scan:**
    ```bash
    python3 checkNpm.py
    ```
    Analyzes packages, displaying only those with `install` or `postinstall` scripts.

*   **Scan All Packages:**
    ```bash
    python3 checkNpm.py --all
    ```
    Analyzes and displays all packages, regardless of script presence.

*   **Online Scan:**
    ```bash
    python3 checkNpm.py --online
    ```
    Fetches `package.json` information from the npm registry instead of local files.

*   **Verbose Output:**
    ```bash
    python3 checkNpm.py --verbose
    ```
    Shows detailed output for debugging and more information.

*   **MalwareBazaar File Checking**
    ```bash
    python3 checkNpm.py --malwarebazaar full_sha256.txt
    ```
    Uses the MalwareBazaar file to check scripts for known malicious SHA256 hashes.

*   **MalwareBazaar File Checking with Deep Scan**
    ```bash
    python3 checkNpm.py --malwarebazaar full_sha256.txt --deep
    ```
    Uses the MalwareBazaar file to check all files for known malicious SHA256 hashes. Will take a long time to run.

** MalwareBazaar File Checking

Download the MalwareBazaar file and place it in the same directory as the script with the name `full_sha256.txt`. This file contains a list of known malicious SHA256 hashes.

The file can be downloaded and unzipped:
[MalwareBazaar 256 Hashes](https://bazaar.abuse.ch/export/txt/sha256/full/)