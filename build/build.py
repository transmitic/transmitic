import os
import platform
import shutil
import subprocess
from datetime import date

website = "https://transmitic.net"
BINARY_NAME = "transmitic"
if platform.system() == "Windows":
    BINARY_NAME = "transmitic.exe"

print("#### BUILD TRANSMITIC ####")
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

sciter_dir = os.path.join(os.path.dirname(workspace_path), "sciter-js-sdk")
sciter_dll_name = "sciter.dll"
sciter_dll_path = os.path.join(sciter_dir, "bin", "windows", "x64", sciter_dll_name)

# Check prereqs
if platform.system() == "Windows":
    rc_edit_path = os.path.join(workspace_path, "more", "rcedit-x64.exe")
    if not os.path.exists(rc_edit_path):
        raise Exception(f"rcedit not found at {rc_edit_path}")

manifest_path = os.path.join(HERE, "transmitic.exe.manifest")
print(f"manifest path: {manifest_path}")

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

# Build
cargo_build_cmd = "cargo build -p transmitic --release"
print(f"cargo build command {cargo_build_cmd}")

res = subprocess.run(cargo_build_cmd, check=True, shell=True)
print(res)

transmitic_exe_path = os.path.join(
    workspace_path, "target", "release", BINARY_NAME
)

new_release_root_dir = new_release_dir = os.path.join(
    workspace_path, "releases", f"a_staging_transmitic_v{version}"
)
new_release_dir = os.path.join(
    new_release_root_dir, "windows"
)
if os.path.exists(new_release_dir):
    shutil.rmtree(new_release_dir)
os.makedirs(new_release_dir, exist_ok=False)
print(f"release dir: {new_release_dir}")

# Copy transmitic.exe
new_path = os.path.join(new_release_dir, BINARY_NAME)
shutil.copy2(transmitic_exe_path, new_path)
transmitic_exe_path = new_path

# copy sciter.dll
new_path = os.path.join(new_release_dir, sciter_dll_name)
shutil.copy2(sciter_dll_path, new_path)
sciter_dll_path = new_path

# create res
res_path = os.path.join(new_release_dir, "res")
os.makedirs(res_path, exist_ok=True)
shutil.copytree(transmitic_src_path, res_path, dirs_exist_ok=True)
icon_path = os.path.join(res_path, "window_icon.ico")


def run_rc_edit(file_path):
    # rcedit
    print("\n\n#### rcedit ####")
    cmd = f'{rc_edit_path} "{file_path}" --set-icon "{icon_path}"'
    print(f"add icon: {cmd}")
    print("")
    result = subprocess.run(cmd, check=True)
    print(result)

    cmd = f'{rc_edit_path} "{file_path}" --set-file-version {version}'
    print(f"{cmd}")
    result = subprocess.run(cmd, check=True)
    print(result)

    cmd = f'{rc_edit_path} "{file_path}" --set-product-version {version}'
    print(f"{cmd}")
    result = subprocess.run(cmd, check=True)
    print(result)

    print("")
    cmd = f'{rc_edit_path} "{file_path}" --set-version-string "CompanyName" "Transmitic"'
    print(f"{cmd}")
    result = subprocess.run(cmd, check=True)
    print(result)

    print("")
    cmd = f'{rc_edit_path} "{file_path}" --set-version-string "FileDescription" "Transmitic"'
    print(f"{cmd}")
    result = subprocess.run(cmd, check=True)
    print(result)

    print("")
    cmd = f'{rc_edit_path} "{file_path}" --set-version-string "ProductName" "Transmitic"'
    print(f"{cmd}")
    result = subprocess.run(cmd, check=True)
    print(result)

    print("")
    cmd = f'{rc_edit_path} "{file_path}" --set-version-string "LegalCopyright" "{date.today().year} Transmitic"'
    print(f"{cmd}")
    result = subprocess.run(cmd, check=True)
    print(result)

    print("")
    cmd = f'{rc_edit_path} "{file_path}" --application-manifest "{manifest_path}"'
    print(f"{cmd}")
    result = subprocess.run(cmd, check=True)
    print(result)


if platform.system() == "Windows":
    run_rc_edit(transmitic_exe_path)

# -- Portable dir
portable_dir = os.path.join(new_release_dir, f"transmitic_v{version}_windows_portable")
zip_path = os.path.join(new_release_dir, f"transmitic_v{version}_windows_portable.zip")
sub_portable_dir = os.path.join(portable_dir, f"transmitic_v{version}_windows")
os.makedirs(portable_dir, exist_ok=False)
shutil.copytree(res_path, os.path.join(sub_portable_dir, 'res'), dirs_exist_ok=True)
shutil.copy2(os.path.join(new_release_dir, sciter_dll_name), os.path.join(sub_portable_dir, sciter_dll_name))
shutil.copy2(os.path.join(new_release_dir, BINARY_NAME), os.path.join(sub_portable_dir, BINARY_NAME))
os.chdir(new_release_dir)
shutil.make_archive(f"transmitic_v{version}_windows_portable", 'zip', root_dir=portable_dir)
os.chdir(workspace_path)

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
command = f"wix build {msi_xml_path} -ext WixToolset.UI.wixext"
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

burn_xml_path = os.path.join(new_release_dir, f'transmitic_v{version}_windows_installer.wxs')
output_installer_path = os.path.join(new_release_dir, f'transmitic_v{version}_windows_installer.exe')
with open(burn_xml_path, 'w', encoding='utf-8') as f:
    f.write(text)

# Build burn
os.chdir(new_release_dir)

res = subprocess.run("wix extension add WixToolset.Util.wixext", check=True, shell=True)
print(res)

res = subprocess.run("wix extension add WixToolset.Bal.wixext", check=True, shell=True)
print(res)

command = f"wix build {burn_xml_path} -ext WixToolset.Bal.wixext -ext WixToolset.UI.wixext"
res = subprocess.run(command, check=True, shell=True)
print(res)
os.chdir(workspace_path)

# -- Copy Cargo.lock
shutil.copy2(os.path.join(workspace_path, "Cargo.lock"), new_release_dir)
