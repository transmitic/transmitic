import argparse
import os
import platform
import shutil
import subprocess
import zipfile
from datetime import date
from getpass import getpass

system = platform.system().lower()
if system == "darwin":
    system = "mac"

is_win = system == "windows"
is_mac = system == "mac"
is_linux = system == "linux"

# -- Args
parser = argparse.ArgumentParser(description='Build Transmitic')
parser.add_argument('--no-clean',
                    help='do not clean build space. useful for iteration speed.',
                    action='store_true',
                    )
parser.add_argument('--no-sign',
                    help='do not sign builds. useful for iteration speed.',
                    action='store_true',
                    )
args = parser.parse_args()
print(args)

if args.no_sign and not is_mac:
    assert False

# --

team_id = ""
codesign_pass = ""
website = "https://transmitic.net"
DISPLAY_NAME = "Transmitic"
BINARY_NAME = "transmitic"
if is_win:
    BINARY_NAME = "transmitic.exe"

print("#### BUILD TRANSMITIC ####")
print(system)

HERE = os.path.dirname(os.path.abspath(__file__))
print(f"build script dir {HERE}")

transmitic_dir = os.path.dirname(HERE)
transmitic_src_path = os.path.join(transmitic_dir, "src")
print(f"src path: {transmitic_src_path}")

cargo_path = os.path.join(transmitic_dir, "Cargo.toml")
print(f"cargo path: {cargo_path}")

workspace_path = os.path.dirname(transmitic_dir)
os.chdir(workspace_path)
print(f"workspace path: {workspace_path}")
print(f"cwd: {os.getcwd()}")

if is_win:
    sciter_dir = os.path.join(os.path.dirname(workspace_path), "sciter-js-sdk")
    sciter_dll_name = "sciter.dll"
    sciter_dll_path = os.path.join(sciter_dir, "bin", "windows", "x64", sciter_dll_name)
elif is_linux:
    sciter_dll_name = "libsciter-gtk.so"
    sciter_dll_path = os.path.join(workspace_path, sciter_dll_name)
else:
    assert is_mac, platform
    sciter_dll_name = "libsciter.dylib"
    sciter_dll_path = os.path.join(workspace_path, sciter_dll_name)
print(f"sciter path: {sciter_dll_path}")
assert os.path.exists(sciter_dll_path), sciter_dll_path

# Check prereqs
if is_win:
    rc_edit_path = os.path.join(workspace_path, "more", "rcedit-x64.exe")
    if not os.path.exists(rc_edit_path):
        raise Exception(f"rcedit not found at {rc_edit_path}")

    manifest_path = os.path.join(HERE, "transmitic.exe.manifest")
    print(f"manifest path: {manifest_path}")
    assert os.path.exists(manifest_path), manifest_path

print("\n\n")
# Find cargo version
version = None
with open(cargo_path, "r") as f:
    for line in f.read().splitlines():
        line = line.strip()
        if line.startswith("version"):
            assert version is None, "Multiple versions found in cargo"
            version = line.split("=")[1].strip(" \"'")
print(f"cargo version: {version}")

# -- New release dir

new_release_root_dir = os.path.join(
    workspace_path, "releases", f"a_staging_transmitic_v{version}"
)
new_release_dir = os.path.join(
    new_release_root_dir, system
)
if os.path.exists(new_release_dir):
    shutil.rmtree(new_release_dir)
os.makedirs(new_release_dir, exist_ok=False)
print(f"release dir: {new_release_dir}")

transmitic_exe_path = os.path.join(
    workspace_path, "target", "release", BINARY_NAME
)


# -- Build


def cargo_build():
    if not args.no_clean:
        clean_cmd = "cargo clean"
        result = subprocess.run(clean_cmd, check=True, shell=True)
        print(result)
        assert not os.path.exists(transmitic_exe_path)

    cargo_build_cmd = "cargo build -p transmitic --release"
    print(f"cargo build command {cargo_build_cmd}")
    result = subprocess.run(cargo_build_cmd, check=True, shell=True)
    print(result)


def code_sign(team_idd, code_pass, code_path):
    result = subprocess.run(f'codesign -s "{code_pass}" --deep -v -f -o runtime "{code_path}"', check=True,
                            shell=True)
    print(result)
    result = subprocess.run(f'codesign -dv "{code_path}"', check=True, shell=True, capture_output=True,
                            encoding='utf-8')
    print(result)
    assert f"TeamIdentifier={team_idd}" in result.stderr.strip()


if is_mac:
    if not args.no_sign:
        codesign_pass = getpass("Enter codesign pass: ").strip()
        assert codesign_pass

        team_id = getpass("Enter TeamID: ").strip()
        assert team_id

    # build arm
    res = subprocess.run("rustup default stable-aarch64-apple-darwin", check=True, shell=True)
    print(res)
    cargo_build()
    # check arm
    res = subprocess.run(f'lipo -archs "{transmitic_exe_path}"', check=True, shell=True, capture_output=True,
                         encoding='utf-8')
    print(res)
    assert res.stdout.strip() == "arm64"
    # sign
    if not args.no_sign:
        code_sign(team_id, codesign_pass, transmitic_exe_path)

    # copy arm
    arm_copy_path = os.path.join(new_release_dir, f"transmitic_v{version}_mac_arm")
    shutil.copy2(transmitic_exe_path, arm_copy_path)

    # build x64
    res = subprocess.run("rustup default stable-x86_64-apple-darwin", check=True, shell=True)
    print(res)
    cargo_build()
    # check x64
    res = subprocess.run(f"lipo -archs {transmitic_exe_path}", check=True, shell=True, capture_output=True,
                         encoding='utf-8')
    print(res)
    assert res.stdout.strip() == "x86_64"
    # sign
    if not args.no_sign:
        code_sign(team_id, codesign_pass, transmitic_exe_path)

    # copy x64
    x86_copy_path = os.path.join(new_release_dir, f"transmitic_v{version}_mac_x64")
    shutil.copy2(transmitic_exe_path, x86_copy_path)

    # create universal
    os.chdir(new_release_dir)
    transmitic_exe_path = os.path.join(new_release_dir, BINARY_NAME)
    assert not os.path.exists(transmitic_exe_path)
    res = subprocess.run(f'lipo "{arm_copy_path}" "{x86_copy_path}" -create -output transmitic', check=True, shell=True)
    print(res)
    # check universal
    res = subprocess.run(f'lipo -archs "{transmitic_exe_path}"', check=True, shell=True, capture_output=True,
                         encoding='utf-8')
    print(res)
    assert res.stdout.strip() == 'x86_64 arm64'
    # sign
    if not args.no_sign:
        code_sign(team_id, codesign_pass, transmitic_exe_path)

    os.chdir(workspace_path)

else:
    cargo_build()
    # Copy transmitic.exe
    new_path = os.path.join(new_release_dir, BINARY_NAME)
    shutil.copy2(transmitic_exe_path, new_path)
    transmitic_exe_path = new_path

# copy sciter.dll
new_path = os.path.join(new_release_dir, sciter_dll_name)
shutil.copy2(sciter_dll_path, new_path)
sciter_dll_path = new_path
# sign
if not args.no_sign and is_mac:
    res = subprocess.run(f'codesign -s "{codesign_pass}" --deep -v -f -o runtime "{sciter_dll_path}"', check=True,
                         shell=True)
    print(res)

# create res
res_path = os.path.join(new_release_dir, "res")
os.makedirs(res_path, exist_ok=True)
shutil.copytree(transmitic_src_path, res_path, dirs_exist_ok=True)
icon_path = os.path.join(res_path, "window_icon.ico")


def run_rc_edit(file_path):
    # rcedit
    print("\n\n#### rcedit ####")
    cmmd = f'{rc_edit_path} "{file_path}" --set-icon "{icon_path}"'
    print(f"add icon: {cmmd}")
    print("")
    result = subprocess.run(cmmd, check=True)
    print(result)

    cmmd = f'{rc_edit_path} "{file_path}" --set-file-version {version}'
    print(f"{cmmd}")
    result = subprocess.run(cmmd, check=True)
    print(result)

    cmmd = f'{rc_edit_path} "{file_path}" --set-product-version {version}'
    print(f"{cmmd}")
    result = subprocess.run(cmmd, check=True)
    print(result)

    print("")
    cmmd = f'{rc_edit_path} "{file_path}" --set-version-string "CompanyName" "Transmitic"'
    print(f"{cmmd}")
    result = subprocess.run(cmmd, check=True)
    print(result)

    print("")
    cmmd = f'{rc_edit_path} "{file_path}" --set-version-string "FileDescription" "Transmitic"'
    print(f"{cmmd}")
    result = subprocess.run(cmmd, check=True)
    print(result)

    print("")
    cmmd = f'{rc_edit_path} "{file_path}" --set-version-string "ProductName" "Transmitic"'
    print(f"{cmmd}")
    result = subprocess.run(cmmd, check=True)
    print(result)

    print("")
    cmmd = f'{rc_edit_path} "{file_path}" --set-version-string "LegalCopyright" "{date.today().year} Transmitic"'
    print(f"{cmmd}")
    result = subprocess.run(cmmd, check=True)
    print(result)

    print("")
    cmmd = f'{rc_edit_path} "{file_path}" --application-manifest "{manifest_path}"'
    print(f"{cmmd}")
    result = subprocess.run(cmmd, check=True)
    print(result)


if is_win:
    run_rc_edit(transmitic_exe_path)

# -- Portable dir
portable_dir = os.path.join(new_release_dir, f"transmitic_v{version}_{system}_portable")
zip_path = os.path.join(new_release_dir, f"transmitic_v{version}_{system}_portable.zip")
sub_portable_dir = os.path.join(portable_dir, f"transmitic_v{version}_{system}")
os.makedirs(portable_dir, exist_ok=False)
shutil.copytree(res_path, os.path.join(sub_portable_dir, 'res'), dirs_exist_ok=True)
shutil.copy2(os.path.join(new_release_dir, sciter_dll_name), os.path.join(sub_portable_dir, sciter_dll_name))
shutil.copy2(os.path.join(new_release_dir, BINARY_NAME), os.path.join(sub_portable_dir, BINARY_NAME))
os.chdir(new_release_dir)
shutil.make_archive(f"transmitic_v{version}_{system}_portable", 'zip', root_dir=portable_dir)
if is_linux:
    os.chdir(portable_dir)
    tar_file_name = f"transmitic_v{version}_{system}_portable.tar.gz"
    cmd = f"tar cfz {tar_file_name} transmitic_v{version}_{system}"
    res = subprocess.run(cmd, check=True, shell=True)
    print(res)
    shutil.move(tar_file_name, new_release_dir)
os.chdir(workspace_path)

if is_win:
    # -- Installer MSI
    shutil.copy2(os.path.join(HERE, 'license.rtf'), new_release_dir)
    shutil.copy2(os.path.join(HERE, 'WixUIBannerBmp.png'), new_release_dir)
    shutil.copy2(os.path.join(HERE, 'WixUIDialogBmp.png'), new_release_dir)
    shutil.copy2(os.path.join(HERE, 'transmitic_installed.json'), new_release_dir)

    # Create MSI xml
    with open(os.path.join(HERE, "transmitic_msi.wxs"), 'r', encoding='utf=8') as f:
        text = f.read()
    res_files = os.listdir(res_path)
    res_features = ""
    res_components = ""
    all_component_ids = []
    for f in res_files:
        component_id = f.replace("-", "_")  # - is not valid in wix
        if component_id in all_component_ids:
            raise Exception(f"ComponentID already exists: {component_id}")
        all_component_ids.append(component_id)

        res_features += f'			<ComponentRef Id="{component_id}"/>\n'
        res_components += f"""                    <Component Id="{component_id}">
                              <File Id="{component_id}" KeyPath="yes" Source="res\\{f}">
                              </File>
                        </Component>
    """
    exit_text = f"{website}"
    text = text.format(RES_FEATURES=res_features, RES_COMPONENTS=res_components, VERSION=version, EXIT_TEXT=exit_text)

    msi_xml_path = os.path.join(new_release_dir, f'transmitic_v{version}_windows.wxs')
    with open(msi_xml_path, 'w', encoding='utf-8') as f:
        f.write(text)

    # Build msi
    os.chdir(new_release_dir)
    command = f'wix build "{msi_xml_path}" -ext WixToolset.UI.wixext'
    res = subprocess.run(command, check=True, shell=True)
    print(res)
    os.chdir(workspace_path)
    output_msi_path = os.path.join(new_release_dir, f'transmitic_v{version}_windows.msi')

    # -- Burn Bundle

    # Create Burn xml
    with open(os.path.join(HERE, "transmitic_installer.wxs"), 'r', encoding='utf=8') as f:
        text = f.read()
    vc_redist_path = os.path.join(workspace_path, "vc_redist.x64.exe")
    text = text.format(VERSION=version, WEBSITE=website, MSI_FILE=output_msi_path, VC_REDIST_FILE=vc_redist_path)

    burn_xml_path = os.path.join(new_release_dir, f'Transmitic v{version} Installer Windows.wxs')
    with open(burn_xml_path, 'w', encoding='utf-8') as f:
        f.write(text)

    # Build burn
    os.chdir(new_release_dir)

    res = subprocess.run("wix extension add WixToolset.Util.wixext", check=True, shell=True)
    print(res)

    res = subprocess.run("wix extension add WixToolset.Bal.wixext", check=True, shell=True)
    print(res)

    command = f'wix build "{burn_xml_path}" -ext WixToolset.Bal.wixext -ext WixToolset.UI.wixext'
    res = subprocess.run(command, check=True, shell=True)
    print(res)
    os.chdir(workspace_path)

# Notarize and Create app bundle
if is_mac:

    notary_args = ""
    if not args.no_sign:
        notary_args = getpass("Enter notary args: ").strip()

    os.chdir(new_release_dir)
    # Notarize single binaries
    if not args.no_sign:
        with zipfile.ZipFile('notary_upload.zip', 'w') as z:
            for f in [sciter_dll_name, BINARY_NAME]:
                z.write(f, compress_type=zipfile.ZIP_DEFLATED)

        command = f"xcrun notarytool submit {notary_args} --wait ./notary_upload.zip"
        res = subprocess.run(command, check=True, shell=True)
        print(res)

    # create dirs
    bundle_path = os.path.join(new_release_dir, "Transmitic.app")
    os.makedirs(bundle_path)
    contents_path = os.path.join(bundle_path, "Contents")
    os.makedirs(contents_path)
    macos_path = os.path.join(contents_path, "MacOS")
    os.makedirs(macos_path)
    macos_resources_path = os.path.join(contents_path, "Resources")
    os.makedirs(macos_resources_path)

    # MacOS
    shutil.copy2(sciter_dll_path, macos_path)
    shutil.copy2(transmitic_exe_path, macos_path)
    shutil.copy2(os.path.join(HERE, 'transmitic_installed.json'), macos_path)

    # Resources
    shutil.copytree(res_path, macos_resources_path, dirs_exist_ok=True)
    shutil.copy2(os.path.join(HERE, "Transmitic.icns"), macos_resources_path)

    # Info.plist
    info_plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>

    <key>CFBundleName</key>
    <string>{DISPLAY_NAME}</string>

    <key>CFBundleDisplayName</key>
    <string>{DISPLAY_NAME}</string>

    <key>CFBundleIdentifier</key>
    <string>net.transmitic.Transmitic</string>

    <key>CFBundleVersion</key>
    <string>{version}</string>

    <key>CFBundlePackageType</key>
    <string>APPL</string>

    <key>CFBundleSignature</key>
    <string>tran</string>

    <key>CFBundleExecutable</key>
    <string>{BINARY_NAME}</string>

    <key>CFBundleIconFile</key>
    <string>Transmitic</string>

    </dict>
</plist>"""
    info_plist_path = os.path.join(contents_path, 'Info.plist')
    with open(info_plist_path, 'w', encoding='utf-8') as f:
        f.write(info_plist)

    if not args.no_sign:
        code_sign(team_id, codesign_pass, "Transmitic.app")

        app_notary_name = "Transmitic_notary.zip"
        assert not os.path.exists(app_notary_name)
        zip_command = f'ditto -ck --rsrc --sequesterRsrc --keepParent Transmitic.app "{app_notary_name}"'
        res = subprocess.run(zip_command, check=True, shell=True, capture_output=True, encoding='utf-8')
        print(res)

        command = f"xcrun notarytool submit {notary_args} --wait ./{app_notary_name}"
        res = subprocess.run(command, check=True, shell=True)
        print(res)

        res = subprocess.run(f'xcrun stapler staple Transmitic.app', check=True, shell=True, capture_output=True,
                             encoding='utf-8')
        print(res)
        assert "The staple and validate action worked!" in res.stdout

        zip_name = f"Transmitic v{version} macOS.zip"
        assert not os.path.exists(zip_name)
        zip_command = f'ditto -ck --rsrc --sequesterRsrc --keepParent Transmitic.app "{zip_name}"'
        res = subprocess.run(zip_command, check=True, shell=True, capture_output=True, encoding='utf-8')
        print(res)

    os.chdir(workspace_path)

# -- Copy Cargo.lock
shutil.copy2(os.path.join(workspace_path, "Cargo.lock"), new_release_dir)

# -- Final
print("\n\n###### FINAL ######")
print(version)
if args.no_clean:
    print("WARNING: NOT CLEAN")
if args.no_sign:
    print("WARNING: NOT SIGNED")
