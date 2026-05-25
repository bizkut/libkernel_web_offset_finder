# 🎯 PS5 libkernel_web Clean Burn Offset Finder

A utility to automate downloading and extracting clean burn system call offsets from the decrypted `libkernel_web.sprx` binary of a PlayStation 5 console. 

These offsets enable jailbreaks like **`p2jb-y2jb`** to use clean, branch-free assembly stubs (`mov r10, rcx; syscall; ret`) inside the high-frequency memory-leaking loop. This avoids stack corruption and ROP chain repair cycles, offering **significantly faster exploit runtimes** and **improving console stability**.

---

## 🚀 Features

* **🔌 Zero Dependencies**: Uses standard Python 3 libraries (`struct`, `argparse`, `ftplib`).
* **⚡ Integrated FTP Downloader**: Connects directly to the PS5's FTP server, downloads the correct module, and extracts offsets in a single run.
* **📂 Local File Support**: Allows manual checking of a pre-downloaded `libkernel_web.sprx` file.

---

## 🛠️ Usage

### Option 1: Automatic Download via FTP (Recommended)

1. Make sure your PS5 is on the same local network as your PC.
2. Launch the **`ftpsrv`** (FTP server) payload on your PS5.
3. Find your console's IP address.
4. Run the finder script with your console's IP address (it will automatically connect, download the module, and print the offsets):

```bash
python check_offsets.py --ftp <PS5_IP_ADDRESS>
```

*If your FTP server runs on a custom port (not `2121`):*
```bash
python check_offsets.py --ftp <PS5_IP_ADDRESS> --port <PORT>
```

---

### Option 2: Check Pre-downloaded Local File

If you already downloaded `libkernel_web.sprx` manually (e.g., from `/system/common/lib/libkernel_web.sprx` using a standalone FTP client):

1. Place `libkernel_web.sprx` in the same directory as this script.
2. Run the script pointing to your file:

```bash
python check_offsets.py libkernel_web.sprx
```

---

## 📈 Example Output

When successful, the script parses the ELF program headers and PT_LOAD segments to output virtual offsets ready to copy-paste:

```text
[*] Connecting to PS5 FTP server at 192.168.1.100:2121...
[+] Connected! Downloading /system/common/lib/libkernel_web.sprx...
[+] Download complete: saved to 'libkernel_web.sprx'

[*] Analyzing ELF structure: libkernel_web.sprx...

==================================================
           🎯 PS5 LIBKERNEL CLEAN BURN OFFSETS
==================================================
  CLEAN_SYSCALL_WRAPPER  : 0x1A8D7n
  KQUEUEEX_WRAPPER       : 0x1BDD0n
  GETTIMEOFDAY           : 0x1D150n
==================================================

[+] Success! Copy the lines above to submit them.
```

---

## 🤝 Contribution

If your console's firmware version is not currently present in the exploit's registry:
1. Run this tool on your console.
2. Copy the resulting offsets.
3. Open a GitHub Issue or submit a Pull Request containing your **Firmware Version** and the **Three Offset Values**.
