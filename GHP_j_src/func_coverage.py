from idaapi import *

class FuncCoverage(DBG_Hooks):
    def dbg_bpt(self, tid, ea):
        print "[*] Hit: 0x%08x" % ea
        return

debugger = FuncCoverage()
debugger.hook()

current_addr = ScreenEA()

for function in Functions(SegStart(current_addr), SegEnd(current_addr)):
    AddBpt(function)
    SetBptAttr(function, BPTATTR_FLAGS, 0x0)

num_breakpoints = GetBptQty()
print "[*] Set %d breakpoints." % num_breakpoints