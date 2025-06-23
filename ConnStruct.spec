# ConnStruct.spec

# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['ConnStruct.py'],
    pathex=['.'],
    binaries=[],
    datas=[('webssh', 'webssh'), ('folder_shell_icon.ico', '.')], # Assuming your icon is at the root
    hiddenimports=[
        'PyQt5.QtWebEngineWidgets',
        'paramiko', # Add webssh dependency
        'tornado',  # Add webssh dependency
        # Add any other submodules if PyInstaller still misses them, e.g.:
        'paramiko.transport', 'paramiko.dsskey',
        'tornado.ioloop', 'tornado.web',
    ],
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
    [],
    exclude_binaries=True,
    name='ConnStruct',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    # For GUI release, set console=False and windowed=True
    # For debugging, set console=True and windowed=False (or just console=True)
    console=False,  # Set to False for final GUI
    windowed=True, # Set to True for final GUI
    icon='folder_shell_icon.ico'
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ConnStruct',
)
