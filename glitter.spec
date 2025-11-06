# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import sys

from PyInstaller.utils.hooks import collect_submodules


IS_WINDOWS = sys.platform.startswith("win")

if IS_WINDOWS:
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo,
        StringFileInfo,
        StringStruct,
        StringTable,
        VarFileInfo,
        VarStruct,
        VSVersionInfo,
    )

try:
    ROOT_DIR = Path(__file__).resolve().parent
except NameError:  # pragma: no cover - when spec executed without __file__
    ROOT_DIR = Path.cwd()
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from glitter import __version__ as GLITTER_VERSION


MAIN_SCRIPT = str(ROOT_DIR / "glitter" / "__main__.py")

def _version_tuple(raw: str):
    parts = [int(bit) for bit in raw.split(".") if bit.isdigit()]
    padded = (parts + [0, 0, 0, 0])[:4]
    return tuple(padded)

if IS_WINDOWS:
    VERSION_INFO = VSVersionInfo(
        ffi=FixedFileInfo(
            filevers=_version_tuple(GLITTER_VERSION),
            prodvers=_version_tuple(GLITTER_VERSION),
            mask=0x3F,
            flags=0,
            OS=0x40004,
            fileType=0x1,
            subtype=0x0,
            date=(0, 0),
        ),
        kids=[
            StringFileInfo(
                [
                    StringTable(
                        "040904B0",
                        [
                            StringStruct("CompanyName", "ScarletKc"),
                            StringStruct("FileDescription", "Simple File Transfer CLI"),
                            StringStruct("FileVersion", GLITTER_VERSION),
                            StringStruct("InternalName", "glitter"),
                            StringStruct("LegalCopyright", "Copyright (C) ScarletKc"),
                            StringStruct("OriginalFilename", "glitter.exe"),
                            StringStruct("ProductName", "Glitter"),
                            StringStruct("ProductVersion", GLITTER_VERSION),
                        ],
                    )
                ]
            ),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ],
    )
else:
    VERSION_INFO = None

hiddenimports = []
hiddenimports += collect_submodules('cryptography')

ICON_PATH = str(ROOT_DIR / "assets" / "glitter.ico") if IS_WINDOWS else None


a = Analysis(
    [MAIN_SCRIPT],
    pathex=[str(ROOT_DIR)],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='glitter',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=VERSION_INFO,
    icon=ICON_PATH,
)
