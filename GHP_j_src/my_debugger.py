from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger():
    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False
        self.h_thread = None
        self.context = None
        self.exception = None
        self.exception_address = None
        self.software_breakpoints = {}
        self.first_breakpoint = True
        self.hardware_breakpoints = {}
        self.guarded_pages = []
        self.memory_breakpoints = {}

        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize

    def load(self, path_to_exe):
        creation_flags = DEBUG_PROCESS
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()

        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0
        startupinfo.cb = sizeof(startupinfo)

        if kernel32.CreateProcessA(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information)):
            print "[*] We have successfully launched the process!"
            print "[*] PID: %d" % process_information.dwProcessId
            self.h_process = self.open_process(process_information.dwProcessId)
        else:
            print "[*] Error: 0x%08x." % kernel32.GetLastError()

    def open_process(self, pid):
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        return h_process

    def attach(self, pid):
        self.h_process = self.open_process(pid)

        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
        else:
            print "[*] Unable to attach to the process."

    def run(self):
        while self.debugger_active == True:
            self.get_debug_event()

    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            #raw_input("Press a key to continue...")

            print "Event Code: %d, Thread ID: %d" % (debug_event.dwDebugEventCode,
                                                     debug_event.dwThreadId)
            self.context = self.get_thread_context(thread_id=debug_event.dwThreadId)

            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                self.exception =  debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    print "Access Violation Detected."
                elif self.exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                elif self.exception == EXCEPTION_GUARD_PAGE:
                    print"Guard Page Access Detected."
                elif self.exception == EXCEPTION_SINGLE_STEP:
                    continue_status = self.exception_handler_single_step()

            #self.debugger_active = False
            kernel32.ContinueDebugEvent(debug_event.dwProcessId,
                                       debug_event.dwThreadId,
                                       continue_status)

    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print "[*] Finished debugging. Exiting..."
            return True
        else:
            print "There was an error"
            return False

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

        if h_thread is not 0:
            return h_thread
        else:
            print "[*] Could not obtain a valid thread handle."
            return False

    def enumerate_threads(self):
        thread_entry = THREADENTRY32()
        thread_list = []

        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
        if snapshot is not None:
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot, byref(thread_entry))

            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(snapshot, byref(thread_entry))

            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False

    def get_thread_context(self, thread_id=None, h_thread=None):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        if h_thread == None:
            h_thread = self.open_thread(thread_id=thread_id)
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        else:
            return False

    def exception_handler_breakpoint(self):
        print "[*] Inside the breakpoint handler."
        print "Exception Address: 0x%08x" % self.exception_address
        return DBG_CONTINUE

    def read_process_memory(self, address, length):
        data = ""
        read_buf = create_string_buffer(length)
        count = c_ulong(0)

        if not kernel32.ReadProcessMemory(self.h_process,
                                          address,
                                          read_buf,
                                          length,
                                          byref(count)):
            return False
        else:
            data += read_buf.raw
            return data

    def write_process_memory(self, address, data):
        count = c_ulong(0)
        length = len(data)

        c_data = c_char_p(data[count.value:])

        if not kernel32.WriteProcessMemory(self.h_process,
                                           address,
                                           c_data,
                                           length,
                                           byref(count)):
            return False
        else:
            return True

    def bp_set_sw(self, address):
        print "[*] Settingbreakpoint at: 0x%08x" % address
        if not self.software_breakpoints.has_key(address):
            try:
                original_byte = self.read_process_memory(address, 1)
                self.write_process_memory(address, "\xCC")
                self.software_breakpoints[address] = (address, original_byte)
            except:
                return False

        return True

    def func_resolve(self, dll, function):
        handle = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, function)

        kernel32.CloseHandle(handle)

        return address

    def bp_set_hw(self, address, length, condition):
        if length not in (1, 2, 4):
            return False
        else:
            length -= 1

        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False

        if not self.hardware_breakpoints.has_key(0):
            available = 0
        elif not self.hardware_breakpoints.has_key(1):
            available = 1
        elif not self.hardware_breakpoints.has_key(2):
            available = 2
        elif not self.hardware_breakpoints.has_key(3):
            available = 3
        else:
            return False

        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)
            context.Dr7 |= 1 << (available * 2)

            if available == 0:
                context.Dr0 = address
            elif available == 1:
                context.Dr1 = address
            elif available == 2:
                context.Dr2 = address
            elif available == 3:
                context.Dr3 = address

            context.Dr7 |= condition << ((available * 4) + 16)
            context.Dr7 |= length << ((available * 4) + 18)

            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

        self.hardware_breakpoints[available] = (address, length, condition)

        return True

    def exception_handler_single_step(self):
        print "[*] Exception address: 0x%08x" % self.exception_address

        if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
            slot = 0
        elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
            slot = 1
        elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
            slot = 2
        elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
            slot = 3
        else:
            continue_status = DBG_EXCEPTION_NOT_HANDLED

        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE

        print "[*] Hardware breakpoint removed."
        return continue_status

    def bp_del_hw(self, slot):
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            context.Dr7 &= ~(1 << (slot * 2))
            if slot == 0:
                context.Dr0 = 0x0
            elif slot == 1:
                context.Dr1 = 0x0
            elif slot == 2:
                context.Dr2 = 0x0
            elif slot == 3:
                context.Dr3 = 0x0

            context.Dr7 &= ~(3 << ((slot * 4) + 16))
            context.Dr7 &= ~(3 << ((slot * 4) + 18))

            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

        del self.hardware_breakpoints[slot]
        return True

    def bp_set_mem(self, address, size):
        mbi = MEMORY_BASIC_INFORMATION()

        if kernel32.VirtualQueryEx(self.h_process, address, byref(mbi), sizeof(mbi)) < sizeof(mbi):
            return False

        current_page = mbi.BaseAddress

        while current_page <= address + size:
            self.guarded_pages.append(current_page)
            old_protection = c_ulong(0)
            if not kernel32.VirtualProtectEx(self.h_process, current_page, size,
                                             mbi.Protect | PAGE_GUARD,
                                             byref(old_protection)):
                return False

            current_page += self.page_size

        self.memory_breakpoints[address] = (address, size, mbi)
        return True
