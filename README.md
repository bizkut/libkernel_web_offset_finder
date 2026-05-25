# 🎯 PS5 Offset Finder

A utility to automate downloading and extracting clean burn system call offsets from the decrypted `libkernel_web.sprx` binary of a PlayStation 5 console. 

These offsets enable jailbreaks like **`p2jb-y2jb`** to use clean, branch-free assembly stubs (`mov r10, rcx; syscall; ret`) inside the high-frequency memory-leaking loop. This avoids stack corruption and ROP chain repair cycles, offering **significantly faster exploit runtimes** and **improving console stability**.

---

## 🚀 Features

* **🔌 Zero Dependencies**: Uses standard Python 3 libraries (`struct`, `argparse`, `ftplib`, `urllib`).
* **🤖 Auto-Bootstrapping**: If the FTP port is closed on your console, the script automatically fetches the `ftpsrv-ps5.elf` payload from GitHub and injects it to your console's payload listener (port `9021`).
* **⚡ Integrated FTP Downloader**: Connects directly to the PS5's FTP server, downloads the correct module, and extracts offsets in a single run.
* **📂 Local File Support**: Allows manual checking of a pre-downloaded `libkernel_web.sprx` file.

---

## 🛠️ Usage

### Option 1: Automatic Download via FTP (Recommended)

> [!WARNING]  
> **A Jailbroken PS5 is required** for this option. Your console must already have run the exploit successfully and be listening on port `9021` (payload port) or running the **`ftpsrv`** payload on port `2121` to allow module extraction.

1. Make sure your PS5 is on the same local network as your PC.
2. Launch the payload listener (port `9021`) on your PS5 (or launch the **`ftpsrv`** payload directly).
3. Find your console's IP address.
4. Run the finder script with your console's IP address:

```bash
python check_offsets.py --ftp <PS5_IP_ADDRESS>
```

> [!NOTE]  
> If the script detects that the FTP server (port `2121`) is not running, it will automatically download `ftpsrv-ps5.elf` and inject it raw to port `9021`, wait 3 seconds for it to spin up, and then proceed to download `libkernel_web.sprx`.

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

## 📈 Example Output (With Auto-Bootstrapping)

```text
[*] Port 2121 is closed. Attempting to bootstrap ftpsrv automatically...
[*] Fetching ftpsrv payload from https://github.com/ps5-payload-dev/ftpsrv/releases/download/v0.20/ftpsrv-ps5.elf...
[+] Downloaded ftpsrv-ps5.elf (345920 bytes)
[*] Sending payload to PS5 (injecting to port 9021)...
[+] Payload successfully sent! Waiting 3 seconds for FTP server to spin up...
[*] Connecting to PS5 FTP server at 192.168.1.100:2121...
[+] Connected! Downloading /system/common/lib/libkernel_web.sprx...
[+] Download complete: saved to 'libkernel_web.sprx'

[*] Analyzing ELF structure: libkernel_web.sprx...

==================================================
           🎯 PS5 LIBKERNEL CLEAN BURN OFFSETS
==================================================
  CLEAN_SYSCALL_WRAPPER  : 0x1A8D7n
  GETTIMEOFDAY           : 0x1D150n
==================================================

[+] Success! Copy the lines above to submit them.
```

---

## 🤝 Contribution

If your console's firmware version is not currently present in the exploit's registry:
1. Run this tool on your console.
2. Copy the resulting offsets.
3. Open a GitHub Issue containing your **Firmware Version** and the **Two Offset Values** directly here:
   👉 **[Submit Offsets Here](https://github.com/bizkut/P2JB-Y2JB-Porting/issues)**
