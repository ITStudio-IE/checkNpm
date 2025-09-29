# TODO List
## TODO
- Add support for external list of malicious SHA256 hashes and files
- Add support for checking for known malicious packages (where do we get this list? since npm doesn't publish this, I think)
- Add more checks for:
    - Heuristic checks (e.g., various keywords in install/postinstall scripts, like 'aws', 'gcp', 'gh', etc)
- Do we want to do the npm install and check inside a Docker container instead of inside the specific project?
    - We might also do the npm install inside a temp directory.

## DONE
- Don't use npm view. This is slow and can be slowed down by the network. Rather use the package.json file directly (already downloaded).
    - Added an --online option to force using npm view, default is to use the local package.json file
- Add MalwareBazaar file checking
    - Signature checks (Where do we get malicious signatures?)
