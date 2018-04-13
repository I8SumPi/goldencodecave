import argparse
import os
import sys
if sys.version_info[0] == 2:
    input = raw_input
try:
    import pefile
except:
    print("[-] Can't find the module pefile.")
    if input("[?] Do you want to install this module ? (y/n) ") != 'n':
        os.system("%s -m pip install pefile"%sys.executable)
    else:
        sys.exit(0)

try:
    from colorama import Fore, Back, Style, init
    init()
except:
    print("[-] Can't find the module colorama.")
    if input("[?] Do you want to install this module ? (y/n) ") != 'n':
        os.system("%s -m pip install colorama"%sys.executable)
    else:
        sys.exit(0)

def main(target, size, byte):
    try:
        pe = pefile.PE(target)
    except IOError as e:
        print(e)
        sys.exit(0)
    except pefile.PEFormatError as e:
        print("[-] %s" % e.args[0])
        sys.exit(0)
    
    image_base = pe.OPTIONAL_HEADER.ImageBase
    print(Style.BRIGHT + Fore.GREEN + "[+] Minimum code cave size: %d"%size)
    print("[+] Byte to find: 0x%02X"%byte)
    print("[+] ImageBase:  0x%08X"%image_base)
    print("[+] EntryPoint: 0x%08X"%pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
        print(Style.BRIGHT + Fore.YELLOW + "[!] ASLR is enabled. Virtual Address (VA) could be different once loaded in memory.")
    
    f = open(target, 'rb')
    print(Style.BRIGHT + Fore.CYAN + "[~] Looking for code cave...\n")
    nb = 0
    for section in pe.sections:
        if section.SizeOfRawData != 0:
            pos = 0
            count = 0
            f.seek(section.PointerToRawData, 0)
            data = f.read(section.SizeOfRawData)

            for b in data:
                pos += 1
                if b == byte:
                    count += 1
                else:
                    if count >= size:
                        nb += 1
                        raw_addr = section.PointerToRawData + pos - count - 1
                        virtual_addr = image_base + section.VirtualAddress + pos - count - 1
                        print(Style.BRIGHT + Fore.GREEN + "[+] Found code cave !" + Fore.RESET + Style.NORMAL + """
Section:             %s
Characteristics:     0x%08X
Raw Size:            %d
~> Code cave size:   %d
    Raw address:     0x%08X
    Virtual address: 0x%08X\n""" % (section.Name.decode(), section.Characteristics,
                                section.SizeOfRawData, count, raw_addr,  virtual_addr))
                    count = 0
    pe.close()
    f.close()

    print(Style.BRIGHT + Fore.GREEN + "[+] %d code cave found !"%nb)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find code cave in PE files")
    parser.add_argument("-f", "--file", dest="file_name", action="store", required=True, help="Target PE File", type=str)
    parser.add_argument("-sc", "--shelcode", dest="shellcode", action="store", default="", help="Shellcode File", type=str)
    parser.add_argument("-s", "--size", dest="size", action="store", default=250, help="Minimum code cave size", type=int)
    parser.add_argument("-b", "--byte", dest="byte", action="store", default=0x00, help="Byte to find", type=int)

    args = parser.parse_args()
    size = 0
    if args.file_name and os.path.exists(args.file_name):
        if args.shellcode and os.path.exists(args.shelcode):
            size = os.path.getsize(args.shelcode)
        elif args.size:
            size = args.size
        if args.byte > 0xFF:
            print(Style.BRIGHT + Fore.RED + "[-] The byte to find is bigger than 0xFF (255). It is now set to 0x00.")
            args.byte = 0x00
        elif args.byte < 0x00:
            print(Style.BRIGHT + Fore.RED + "[-] The byte to find is bigger than 0xFF (255). It is now set to 0x00.")
            args.byte = 0x00
        main(args.file_name, size, args.byte)
    else:
        parser.print_help()
        sys.exit(0)