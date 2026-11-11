# Third-party tools and rights

The included Python application imports the Python standard library and ACP modules. No third-party Python package, node_modules tree, virtual-machine image, Kandev source or VMware runtime is bundled. A runtime dependency scan is not a legal ownership opinion.

Separately obtained components have their own terms:

- Python and SQLite: runtime facilities provided by the user's Python installation.
- Git: used for repository inspection and disposable test repositories.
- Node.js: optional legacy Kandev cancellation helper requires built-in WebSocket support (historical guide: Node 22+).
- Kandev: optional external service/API adapter. The project's historical assessment identified GNU AGPLv3 licensing. Confirm the exact upstream version and obligations before using, modifying, combining or distributing it.
- VMware Workstation and its vmrun/VIX components: separately installed proprietary/vendor software. No installer or license entitlement is supplied.
- Ubuntu/Linux: historical disposable guest environment; no guest image or distro packages are redistributed.

The MIT License covers only the rights the owner can grant in this repository. It does not relicense any of these external tools. No trademark endorsement or affiliation is implied, including by the mention of dot.
