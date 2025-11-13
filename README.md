# 🔒 FUSE Backup Filesystem

A simple **FUSE (Filesystem in Userspace)** project written in **C** that automatically creates **backup copies** of any files you modify inside the mounted filesystem.  
Perfect for learning how FUSE works or for experimenting with virtual filesystems on Linux.

---

## 🚀 Features

- Transparent passthrough filesystem — behaves like a normal directory.
- Automatically backs up every file you create or modify.
- Mirrors folder structure in a specified backup directory.
- Optional **AES-256 encryption** for backup copies using OpenSSL.
- Easy to compile and run on **Ubuntu** (tested inside Oracle VirtualBox).

---

## 🧰 Requirements

- Ubuntu (any recent version)
- `libfuse3-dev`
- `pkg-config`
- `gcc` / `build-essential`
- `openssl` *(only if you use encryption)*

Install dependencies:
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libfuse3-dev openssl

🏗️ Building the Project

Clone your repository and build:
git clone https://github.com/prajwalkorde/guardfs
cd fuse-backup
make


📁 Directory Setup

Create the directories for testing:
mkdir -p mirror_root backup_root mountpoint
echo "hello world" > mirror_root/hello.txt


▶️ Running the Filesystem

Run it as your user (recommended):
./backupfs --mirror "$(pwd)/mirror_root" --backup "$(pwd)/backup_root" mountpoint -f

In another terminal:
echo "new data" > mountpoint/test.txt
echo "more data" >> mountpoint/test.txt


You’ll now find a copy of test.txt inside your backup_root directory!

Unmount when finished:
fusermount3 -u mountpoint

🔐 Optional: Encrypted Backups

To automatically encrypt all backups using AES-256-CBC via OpenSSL:

./backupfs --mirror "$(pwd)/mirror_root" --backup "$(pwd)/backup_root" \
  --encrypt-backups --enc-key "mysecretkey" mountpoint -f












