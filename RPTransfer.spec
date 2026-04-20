# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for a single-file, minimal-size rptransfer.exe.
#
# Build:
#     build-venv/Scripts/pyinstaller --clean RPTransfer.spec
#
# Notes:
#   - The spec is tuned for a *clean* venv that only has paramiko, keyring,
#     and pyinstaller. The `excludes` list is a belt-and-suspenders guard so
#     that even in a contaminated environment PyInstaller will not pull in
#     the usual data-science stack.
#   - `optimize=2` strips docstrings and asserts from bundled .pyc files.
#   - UPX shrinks the final exe by roughly a third; it is picked up from
#     ./tools/upx/ automatically when `--upx-dir tools/upx` is passed or
#     when upx is on PATH. The spec just enables UPX; the directory is
#     supplied on the pyinstaller command line.
#   - rptransfer.ico is bundled so the running exe can show the icon via
#     sys._MEIPASS; config loading is handled separately by resource_path()
#     in RPTransfer.py and always uses the exe's directory.

EXCLUDES = [
    # Science / ML stack (never imported by RPTransfer)
    'numpy', 'pandas', 'scipy', 'matplotlib', 'sklearn',
    'cv2', 'torch', 'tensorflow', 'numba', 'sympy',
    # Imaging
    'PIL', 'Pillow',
    # Alternative GUI toolkits
    'PyQt5', 'PyQt6', 'PySide2', 'PySide6', 'wx',
    # Notebooks / dev tooling
    'IPython', 'ipykernel', 'jupyter', 'notebook', 'sphinx', 'pytest',
    # Misc fat deps sometimes pulled in transitively
    'lxml', 'babel', 'docutils',
    # Stdlib chunks unused by RPTransfer (safe to drop — paramiko does not
    # need these and PyInstaller hooks don't reference them)
    'pydoc_data', 'test', 'tkinter.test',
]

a = Analysis(
    ['RPTransfer.py'],
    pathex=[],
    binaries=[],
    datas=[('rptransfer.ico', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=2,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='rptransfer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[
        # api-ms-win-*.dll are tiny stubs and can be broken by UPX on some
        # Windows versions. Everything else (including python*.dll and
        # tcl/tk DLLs) compresses cleanly in practice.
        'api-ms-win-*.dll',
        'vcruntime140.dll',
        'ucrtbase.dll',
    ],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['rptransfer.ico'],
)
