#!/usr/bin/env python3
import sys
import struct
import argparse
import socket
import time
import json
import re
import urllib.request
from ftplib import FTP

DEFAULT_FTP_PORT = 2121
DEFAULT_SPRX_PATH = "/system/common/lib/libkernel_web.sprx"
LOCAL_TEMP_NAME = "libkernel_web.sprx"

GITHUB_API_URL = "https://api.github.com/repos/ps5-payload-dev/ftpsrv/releases/latest"
FALLBACK_ELF_URL = "https://github.com/ps5-payload-dev/ftpsrv/releases/download/v0.20/ftpsrv-ps5.elf"
PAYLOAD_PORT = 9021

def is_port_open(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def get_latest_ftpsrv_url():
    print("[*] Querying GitHub API for the latest ftpsrv release...")
    try:
        req = urllib.request.Request(
            GITHUB_API_URL, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            release_info = json.loads(response.read().decode('utf-8'))
            
        for asset in release_info.get("assets", []):
            if asset.get("name") == "ftpsrv-ps5.elf":
                download_url = asset.get("browser_download_url")
                tag_name = release_info.get("tag_name", "latest")
                print(f"[+] Found latest release asset: {asset.get('name')} ({tag_name})")
                return download_url
    except Exception as e:
        print(f"[*] GitHub API query failed or rate-limited: {e}")
        print(f"[*] Falling back to default URL: {FALLBACK_ELF_URL}")
        
    return FALLBACK_ELF_URL

def bootstrap_ftpsrv(host):
    print(f"[*] Port {DEFAULT_FTP_PORT} is closed. Attempting to bootstrap ftpsrv automatically...")
    
    download_url = get_latest_ftpsrv_url()
    print(f"[*] Fetching ftpsrv payload from {download_url}...")
    try:
        req = urllib.request.Request(
            download_url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            elf_data = response.read()
        print(f"[+] Downloaded ftpsrv-ps5.elf ({len(elf_data)} bytes)")
    except Exception as e:
        print(f"[-] Failed to download ftpsrv payload: {e}", file=sys.stderr)
        return False

    print(f"[*] Sending payload to PS5 (injecting to port {PAYLOAD_PORT})...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((host, PAYLOAD_PORT))
            s.sendall(elf_data)
        print("[+] Payload successfully sent! Waiting 3 seconds for FTP server to spin up...")
        time.sleep(3)
        return True
    except Exception as e:
        print(f"[-] Failed to inject payload to port {PAYLOAD_PORT}: {e}", file=sys.stderr)
        return False

def download_via_ftp(host, port, remote_path, local_path):
    # Check if the FTP port is open
    if not is_port_open(host, port):
        # Port is closed, try to bootstrap ftpsrv
        bootstrapped = bootstrap_ftpsrv(host)
        if not bootstrapped:
            print("[-] Aborting: FTP server is not running and auto-bootstrapping failed.", file=sys.stderr)
            return False
            
        # Re-check port after bootstrapping
        if not is_port_open(host, port):
            print(f"[-] Aborting: FTP server was injected but port {port} is still closed.", file=sys.stderr)
            return False

    print(f"[*] Connecting to PS5 FTP server at {host}:{port}...")
    try:
        ftp = FTP()
        ftp.connect(host, port, timeout=10)
        ftp.login()
        
        print(f"[+] Connected! Downloading {remote_path}...")
        with open(local_path, 'wb') as f:
            ftp.retrbinary(f"RETR {remote_path}", f.write)
            
        ftp.quit()
        print(f"[+] Download complete: saved to '{local_path}'")
        return True
    except Exception as e:
        print(f"[-] FTP Error: {e}", file=sys.stderr)
        return False

def check_elf(filepath, fw_version=None):
    print(f"\n[*] Analyzing ELF structure: {filepath}...")
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"[-] Failed to read file: {e}", file=sys.stderr)
        return

    # Verify ELF magic
    if data[:4] != b'\x7fELF':
        print("[-] Error: Not a valid ELF file!")
        return

    # ELF64 Header fields
    e_entry, e_phoff, e_shoff = struct.unpack_from('<QQQ', data, 0x18)
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]

    # Find PT_LOAD segments to map File Offset to virtual address (Vaddr)
    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from('<IIQQQQQQ', data, off)
        if p_type == 1: # PT_LOAD
            segments.append((p_offset, p_filesz, p_vaddr))

    def get_vaddr(file_offset):
        for p_offset, p_filesz, p_vaddr in segments:
            if p_offset <= file_offset < p_offset + p_filesz:
                return p_vaddr + (file_offset - p_offset)
        return None

    results = {}

    # 1. Search for CLEAN_SYSCALL_WRAPPER
    # Pattern: mov r10, rcx; syscall; ret -> 49 89 CA 0F 05 C3
    pattern_clean = b'\x49\x89\xCA\x0F\x05\xC3'
    idx = data.find(pattern_clean)
    if idx != -1:
        vaddr = get_vaddr(idx)
        if vaddr is not None:
            results['CLEAN_SYSCALL_WRAPPER'] = vaddr

    # 2. Search for GETTIMEOFDAY
    # Pattern: mov rax, 0x74; mov r10, rcx; syscall -> 48 C7 C0 74 00 00 00 49 89 CA 0F 05
    pattern_gtod = b'\x48\xC7\xC0\x74\x00\x00\x00\x49\x89\xCA\x0F\x05'
    idx = data.find(pattern_gtod)
    if idx != -1:
        vaddr = get_vaddr(idx)
        if vaddr is not None:
            results['GETTIMEOFDAY'] = vaddr

    # Try to extract version from filename if not explicitly provided
    if fw_version is None:
        match = re.search(r"(\d+\.\d+)", filepath)
        if match:
            fw_version = match.group(1)

    # Print final structured results
    print("\n" + "="*50)
    print("           🎯 PS5 LIBKERNEL CLEAN BURN OFFSETS")
    print("="*50)
    
    if fw_version:
        print(f"  PlayStation 5 Firmware : {fw_version}")
    else:
        print(f"  PlayStation 5 Firmware : [Please specify firmware when submitting]")
        
    print("-"*50)
        
    missing = []
    for key in ['CLEAN_SYSCALL_WRAPPER', 'GETTIMEOFDAY']:
        if key in results:
            print(f"  {key:<22} : 0x{results[key]:X}n")
        else:
            print(f"  {key:<22} : NOT FOUND")
            missing.append(key)
            
    print("="*50)
    if not missing:
        print("\n[+] Success! Copy the lines above to submit them.")
        print("[-] Report offsets here: https://github.com/bizkut/P2JB-Y2JB-Porting/issues")
        if not fw_version:
            print("[*] Don't forget to include the target firmware version!")
    else:
        print(f"\n[-] Warning: Could not locate offsets for: {', '.join(missing)}")

def main():
    parser = argparse.ArgumentParser(
        description="PS5 libkernel_web.sprx Clean Burn Offset Finder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  1. Automatically download via FTP and extract offsets:
     python check_offsets.py --ftp 192.168.1.100

  2. Use a custom FTP port:
     python check_offsets.py --ftp 192.168.1.100 --port 2121

  3. Extract offsets from an already downloaded local file:
     python check_offsets.py libkernel_web.sprx
"""
    )
    
    parser.add_argument("file", nargs="?", help="Path to local decrypted libkernel_web.sprx")
    parser.add_argument("--ftp", metavar="IP", help="PS5 Console IP Address to download decrypted SPRX via FTP")
    parser.add_argument("--port", type=int, default=DEFAULT_FTP_PORT, help=f"FTP Port (default: {DEFAULT_FTP_PORT})")
    parser.add_argument("--remote-path", default=DEFAULT_SPRX_PATH, help=f"Remote path to SPRX (default: {DEFAULT_SPRX_PATH})")
    parser.add_argument("--fw", help="Explicitly set the PlayStation 5 firmware version")
    
    args = parser.parse_args()
    
    fw_version = args.fw
    
    if args.ftp:
        success = download_via_ftp(args.ftp, args.port, args.remote_path, LOCAL_TEMP_NAME)
        if success:
            check_elf(LOCAL_TEMP_NAME, fw_version=fw_version)
    elif args.file:
        check_elf(args.file, fw_version=fw_version)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
