# KT Run Viewer (Offline)

This is a zero-dependency, offline viewer for KT run artifacts.

## Usage

Option A (direct):
- Open `index.html` in a browser.
- Use the file picker to select artifacts from a single run directory.

Option B (local static server; built-in):
- From this folder: `python -m http.server`
- Open `http://localhost:8000/` and load files.

## Notes
- No network requests are made.
- No external JS/CSS assets are used.
- This is a viewer only; it does not execute KT tools.

