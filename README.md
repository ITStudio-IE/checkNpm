# checkNpm.py

## Purpose
Identifies suspicious `postinstall` and `install` scripts, and known malicious SHA256 hashes within `package.json` files of Node.js packages.

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
