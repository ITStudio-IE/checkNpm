# TODO List

## TODO
- Add support for external list of malicious SHA256 hashes and files
- Add support for checking for known malicious packages
- Add more checks for:
    - Heuristic checks (e.g., various keywords in install/postinstall scripts, like 'aws', 'gcp', 'gh', etc)
    - Signature checks (Where do we get malicious signatures?)

## DONE
- Don't use npm view. This is slow and can be slowed down by the network. Rather use the package.json file directly (already downloaded).
