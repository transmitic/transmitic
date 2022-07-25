import os
import shutil
import subprocess
from datetime import date

print("#### BUILD TRANSMITIC ####")
HERE = os.path.dirname(os.path.abspath(__file__))
print(f"build script dir {HERE}")
cargo_path = os.path.join(HERE, "cargo.toml")
print(f"cargo path: {cargo_path}")
transmitic_src_path = os.path.join(HERE, "src")
print(f"src path: {transmitic_src_path}")

workspace_path = os.path.dirname(HERE)
os.chdir(workspace_path)
print(f"workspace path: {workspace_path}")
print(f"cwd: {os.getcwd()}")

# Check prereqs
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

result = subprocess.run(cargo_build_cmd, check=True)
print(result)

transmitic_exe_path = os.path.join(
    workspace_path, "target", "release", "transmitic.exe"
)

new_release_dir = os.path.join(
    workspace_path, "releases", f"a_staging_transmitic_v{version}"
)
os.makedirs(new_release_dir, exist_ok=True)
print(f"release dir: {new_release_dir}")

# Copy transmitic.exe
new_path = os.path.join(new_release_dir, "transmitic.exe")
shutil.copy2(transmitic_exe_path, new_path)
transmitic_exe_path = new_path

# create res
res_path = os.path.join(new_release_dir, "res")
os.makedirs(res_path, exist_ok=True)
shutil.copytree(transmitic_src_path, res_path, dirs_exist_ok=True)
icon_path = os.path.join(res_path, "window_icon.ico")

# rcedit
print("\n\n#### rcedit ####")
cmd = f'{rc_edit_path} "{transmitic_exe_path}" --set-icon "{icon_path}"'
print(f"add icon: {cmd}")
print("")
result = subprocess.run(cmd, check=True)
print(result)

cmd = f'{rc_edit_path} "{transmitic_exe_path}" --set-file-version {version}'
print(f"{cmd}")
result = subprocess.run(cmd, check=True)
print(result)

cmd = f'{rc_edit_path} "{transmitic_exe_path}" --set-product-version {version}'
print(f"{cmd}")
result = subprocess.run(cmd, check=True)
print(result)

print("")
cmd = f'{rc_edit_path} "{transmitic_exe_path}" --set-version-string "CompanyName" "Transmitic"'
print(f"{cmd}")
result = subprocess.run(cmd, check=True)
print(result)

print("")
cmd = f'{rc_edit_path} "{transmitic_exe_path}" --set-version-string "FileDescription" "Transmitic"'
print(f"{cmd}")
result = subprocess.run(cmd, check=True)
print(result)

print("")
cmd = f'{rc_edit_path} "{transmitic_exe_path}" --set-version-string "ProductName" "Transmitic"'
print(f"{cmd}")
result = subprocess.run(cmd, check=True)
print(result)

print("")
cmd = f'{rc_edit_path} "{transmitic_exe_path}" --set-version-string "LegalCopyright" "{date.today().year} Transmitic"'
print(f"{cmd}")
result = subprocess.run(cmd, check=True)
print(result)

print("")
cmd = f'{rc_edit_path} "{transmitic_exe_path}" --application-manifest "{manifest_path}"'
print(f"{cmd}")
result = subprocess.run(cmd, check=True)
print(result)