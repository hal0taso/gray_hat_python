import my_debugger
from my_debugger_defines import *

debugger = my_debugger.debugger()

#debugger.load("C:\\WINDOWS\\system32\\calc.exe")
pid = raw_input("Enter the PID of the process to attach to: ")

debugger.attach(int(pid))

printf_address = debugger.func_resolve("msvcrt.dll", "printf")
print "[*] Address of printf: 0x%08x" % printf_address

#debugger.bp_set_sw(printf_address)
debugger.bp_set_hw(printf_address, 1, HW_EXECUTE)
debugger.run()

#list = debugger.enumerate_threads()
#print list
#for thread in list:
#    thread_context = debugger.get_thread_context(thread)
#
#    print "[*] Dumping registers for thread ID: 0x%08x" % thread
#    print "[**] EIP: 0x%08x" % thread_context.Eip
#    print "[**] ESP: 0x%08x" % thread_context.Esp
#    print "[**] EBP: 0x%08x" % thread_context.Ebp
#    print "[**] EAX: 0x%08x" % thread_context.Eax
#    print "[**] EBX: 0x%08x" % thread_context.Ebx
#    print "[**] ECX: 0x%08x" % thread_context.Ecx
#    print "[**] EDX: 0x%08x" % thread_context.Edx
#    print "[*] END DUMP"

debugger.detach()
