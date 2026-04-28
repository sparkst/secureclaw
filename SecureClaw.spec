# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['/Users/travis/SGDrive/dev/exec-team/projects/019-prompt-injection-attacks/secureclaw/dist/secureclaw.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
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
    name='SecureClaw',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['/Users/travis/SGDrive/dev/exec-team/projects/019-prompt-injection-attacks/secureclaw/assets/SecureClaw.icns'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SecureClaw',
)
app = BUNDLE(
    coll,
    name='SecureClaw.app',
    icon='/Users/travis/SGDrive/dev/exec-team/projects/019-prompt-injection-attacks/secureclaw/assets/SecureClaw.icns',
    bundle_identifier=None,
)
