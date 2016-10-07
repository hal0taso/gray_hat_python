import sys
sys.path.append("C:\\PyEmu")
sys.path.append("C:\\PyEmu\\lib")

from PyEmu import *

def ret_handler(emu, mnemonic, address, op1value, op2value, op3value):
    num1 = emu.get_stack_argument("arg_0")
    num2 = emu.get_stack_argument("arg_4")
    return_value = emu.get_register("eax")

    print "[*] Function took: %d, %d and the result is %d." % (num1, num2, return_value)
    return True

emu = IDAPyEmu()

code_start = SegByName(".text")
code_end = SegEnd(code_start)

while code_start <= code_end:
    emu.set_memory(code_start, GetOriginalByte(code_start), size=1)
    code_start += 1

print "[*] Finished loading code section into memory."

data_start = SegByName(".data")
data_end = SegEnd(data_start)

while data_start <= data_end:
    emu.set_memory(data_start, GetOriginalByte(data_start), size=1)
    data_start += 1

print "[*] Finished loading data section into memory."

emu.set_register("EIP", 0x00401000)
emu.set_mnemonic_handler("ret", ret_handler)

emu.set_stack_argument(0x4, 0x1, name="arg_0")
emu.set_stack_argument(0x8, 0x3, name="arg_4")

emu.execute(steps=10)

print "[*] Finished function emulation run."
