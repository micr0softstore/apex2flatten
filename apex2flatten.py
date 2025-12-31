#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

VERSION = "0.2"

def run(cmd):
    subprocess.check_call(cmd)

def check_root():
    if os.geteuid() != 0:
        print("[!] This script must be run as root")
        sys.exit(1)

def get_target_uid_gid():
    uid = int(os.environ.get("SUDO_UID", os.getuid()))
    gid = int(os.environ.get("SUDO_GID", os.getgid()))
    return uid, gid

def fix_ownership(path, uid, gid):
    for root, dirs, files in os.walk(path, followlinks=False):
        for d in dirs:
            p = os.path.join(root, d)
            os.lchown(p, uid, gid)
            os.chmod(p, 0o755)
        for f in files:
            p = os.path.join(root, f)
            os.lchown(p, uid, gid)
            if not os.path.islink(p):
                os.chmod(p, 0o644)
    os.lchown(path, uid, gid)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Flatten an Android APEX. \nNot supported for android 15 and up\n as google removed flatten apex support from apexd since then.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("--input", help="Path to .apex file")
    parser.add_argument("--version", action="store_true", help="Show version and exit")

    args = parser.parse_args()

    if args.version:
        print(f"apex2flatten version {VERSION}\n\n   by t.me/micr0softstore\n")
        sys.exit(0)

    if not args.input:
        parser.error("--input is required")

    return args

def main():
    check_root()
    args = parse_args()

    apex_path = Path(args.input).resolve()
    if not apex_path.exists() or apex_path.suffix != ".apex":
        print("[!] Invalid .apex file")
        sys.exit(1)

    apex_name = apex_path.stem
    cwd = Path.cwd()
    out_dir = cwd / apex_name

    if out_dir.exists():
        print(f"[!] Output directory already exists: {out_dir}")
        sys.exit(1)

    tmp_zip = tempfile.TemporaryDirectory(prefix="apex_zip_")
    tmp_mount = tempfile.TemporaryDirectory(prefix="apex_mount_")

    has_pubkey = False

    try:
        print("[*] Unpacking APEX zip...")
        run(["unzip", "-q", str(apex_path), "-d", tmp_zip.name])

        payload = Path(tmp_zip.name) / "apex_payload.img"
        if not payload.exists():
            print("[!] apex_payload.img not found")
            sys.exit(1)

        pubkey = Path(tmp_zip.name) / "apex_pubkey"

        print("[*] Mounting apex_payload.img...")
        run(["mount", "-o", "loop,ro", "-t", "ext4", str(payload), tmp_mount.name])

        print("[*] Copying filesystem...")
        shutil.copytree(
            tmp_mount.name,
            out_dir,
            symlinks=True,
            copy_function=shutil.copy2
        )

        if pubkey.exists():
            print("[*] Copying apex_pubkey...")
            shutil.copy2(pubkey, out_dir / "apex_pubkey")
            has_pubkey = True

        print("[*] Exporting permissions and SELinux contexts...")
        perm_file = cwd / "apex_config"
        sectx_file = cwd / "apex_secontexts"

        with perm_file.open("w") as p_out, sectx_file.open("w") as s_out:
            for root, dirs, files in os.walk(tmp_mount.name):
                for name in dirs + files:
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, tmp_mount.name)

                    st = os.lstat(full)
                    mode = oct(st.st_mode & 0o777)
                    p_out.write(f"{rel} {mode}\n")

                    try:
                        ctx = subprocess.check_output(
                            ["ls", "-Zd", full],
                            text=True
                        ).split()[0]
                        s_out.write(f"{rel} {ctx}\n")
                    except Exception:
                        s_out.write(f"{rel} u:object_r:unlabeled:s0\n")

            if has_pubkey:
                p_out.write("apex_pubkey 0o644\n")
                s_out.write("apex_pubkey u:object_r:system_file:s0\n")

        print("[*] Unmounting image...")
        run(["umount", tmp_mount.name])

        uid, gid = get_target_uid_gid()
        print(f"[*] Fixing ownership to UID:{uid} GID:{gid}...")

        fix_ownership(out_dir, uid, gid)
        os.chown(perm_file, uid, gid)
        os.chown(sectx_file, uid, gid)
        os.chmod(perm_file, 0o644)
        os.chmod(sectx_file, 0o644)

        print("[✓] Done")
        print("    apex_pubkey registered explicitly")

    finally:
        subprocess.run(["umount", tmp_mount.name], stderr=subprocess.DEVNULL)
        tmp_zip.cleanup()
        tmp_mount.cleanup()

if __name__ == "__main__":
    main()
