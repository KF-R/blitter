
# Blitter Build instructions 
### Using PyInstaller for Linux/Macos and Windows (_Windows see note below_)

```
git clone https://github.com/KF-R/blitter
mv blitter blitter-build
cd blitter-build/
python3 -m venv venv-blitter-build
source venv-blitter-build/bin/activate
pip install --upgrade pip setuptools wheel
pip install pyinstaller
pip install flask stem requests[socks] cryptography
pyinstaller --clean --hidden-import=nacl.bindings --hidden-import=cffi --hidden-import=cffi.backend_ctypes keygen.py
pyinstaller --clean --add-data "static:static" --add-data "bip39_english.txt:." blitter.py
```

Create a new directory called `blitter`. Copy the contents of `dist/keygen` and `dist/blitter` into it, merging `_internals`, overwrites are fine.

Move/copy the license and readme to `blitter`.

Run `blitter` from the command line so you can keep an eye on the feedback provided.

---

## Windows-specific Pyinstaller syntax:

### Main
On Windows, swap the Linux/MacOS command:

`pyinstaller --clean --add-data "static:static" --add-data "bip39_english.txt:." blitter.py`

for:

`pyinstaller --clean --add-data "static;static" --add-data "bip39_english.txt;." blitter.py`

### Keygen
The Linux/MacOS command remains unchanged for Windows. i.e.

`pyinstaller --clean --hidden-import=nacl.bindings --hidden-import=cffi --hidden-import=cffi.backend_ctypes keygen.py`

---



