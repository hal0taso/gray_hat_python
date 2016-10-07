from immlib import *

def main(args):
    imm = Debugger()

    bad_char_found = False

    address = int(args[0], 16)
    shellcode = "\x90\x90\x90\x80"
    shellcode_length = len(shellcode)

    debug_shellcode = imm.readMemory(address, shellcode_length)

    imm.log("Adress: 0x%08x" % address)
    imm.log("Shellcode Length: %d" % shellcode_length)

    imm.log("Attack Shellcode: 0x%s" % shellcode.encode("HEX"))
    imm.log("In Memory Shellcode: 0x%s" % debug_shellcode.encode("HEX"))

    count = 0
    while count < shellcode_length:
        if debug_shellcode[count] != shellcode[count]:
            imm.log("Bad Char Detected at offset %d" % count)
            bad_char_found = True
            break

        count += 1

    if bad_char_found:
        imm.log("[*****]")
        imm.log("Bad character found: 0x%s" % debug_shellcode[count].encode("HEX"))
        imm.log("Bad character original: 0x%s" % shellcode[count].encode("HEX"))
        imm.log("[*****]")

    return "[*] !badchar finished. check Log window."
