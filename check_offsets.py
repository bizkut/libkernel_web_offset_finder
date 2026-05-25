#!/usr/bin/env python3
import sys
import struct
import argparse
from ftplib import FTP

DEFAULT_FTP_PORT = 2121
DEFAULT_SPRX_PATH = "/system/common/lib/libkernel_web.sprx"
LOCAL_TEMP_NAME = "libkernel_web.sprx"

def download_via_ftp(host, port, remote_path, local_path):
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

def check_elf(filepath):
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

    # 2. Search for KQUEUEEX_WRAPPER
    # Pattern: mov rax, 0x8D; mov r10, rcx; syscall -> 48 C7 C0 8D 00 00 00 49 89 CA 0F 05
    pattern_kq = b'\x48\xC7\xC0\x8D\x00\x00\x00\x49\x89\xCA\x0F\x05'
    idx = data.find(pattern_kq)
    if idx != -1:
        vaddr = get_vaddr(idx)
        if vaddr is not None:
            results['KQUEUEEX_WRAPPER'] = vaddr

    # 3. Search for GETTIMEOFDAY
    # Pattern: mov rax, 0x74; mov r10, rcx; syscall -> 48 C7 C0 74 00 00 00 49 89 CA 0F 05
    pattern_gtod = b'\x48\xC7\xC0\x74\x00\x00\x00\x49\x89\xCA\x0F\x05'
    idx = data.find(pattern_gtod)
    if idx != -1:
        vaddr = get_vaddr(idx)
        if vaddr is not None:
            results['GETTIMEOFDAY'] = vaddr

    # Print final structured results
    print("\n" + "="*50)
    print("           🎯 PS5 LIBKERNEL CLEAN BURN OFFSETS")
    print("="*50)
    
    missing = []
    for key in ['CLEAN_SYSCALL_WRAPPER', 'KQUEUEEX_WRAPPER', 'GETTIMEOFDAY']:
        if key in results:
            print(f"  {key:<22} : 0x{results[key]:X}n")
        else:
            print(f"  {key:<22} : NOT FOUND")
            missing.append(key)
            
    print("="*50)
    if not missing:
        print("\n[+] Success! Copy the lines above to submit them.")
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
    
    args = parser.parse_args()
    
    if args.ftp:
        success = download_via_ftp(args.ftp, args.port, args.remote_path, LOCAL_TEMP_NAME)
        if success:
            check_elf(LOCAL_TEMP_NAME)
    elif args.file:
        check_elf(args.file)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
