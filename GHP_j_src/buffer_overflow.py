from ctypes import *

msvcrt = cdll.msvcrt
raw_input("Once the debugger is attached, press any key.")

buffer = c_char_p("AAAAA")
overflow = "A" * 100

msvcrt.strcpy(buffer, overflow)
