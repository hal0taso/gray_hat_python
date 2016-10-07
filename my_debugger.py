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
        # self.exception_address = None
        self.software_breakpoints = {}
        self.first_breakpoints = True
        self.hardware_breakpoints = {}

        # Here let's determine and store the default
        # page size for the system.
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize

        self.guard_pages = []
        self.memory_breakpoints = {}

    def load(self, path_to_exe):

        # by dwCreationFlags,
        # it decide how to generate process
        # for example, if you want to look at gui of calucurator,
        # you should type "creation_flags = CREATE_NEW_CONSOLE"
        creation_flags = DEBUG_PROCESS

        # instantiate Structure
        startupinfo = STARTUPINFO()
        process_infomation = PROCESS_INFOMATION()

        # Because of next two ooption, started process
        # would be show other window.
        # This is an example that
        # setting about STARTUPINFO Structure
        # effects a debug target
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        # init var `cb` that show size of STARTUPINFO Structure
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
                                   byref(process_infomation)):

            print "[*] We have successfully launched the proccess!"
            print "[*] PID: %d" % process_infomation.dwProcessId

            # get handle of process
            # and save for use in future
            self.h_process = self.open_process(process_infomation.dwProcessId)

        else:
            print "[*] Error: 0x%08x." % kernel32.GetLastError()

    def open_process(self,pid):
            
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid)
        return h_process


    def attach(self,pid):

        self.h_process = self.open_process(pid)

        # try to attach to process
        # if it failed, back to invoker
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
        else:
            print "[*] Unable to attach to the process."

    def run(self):
        # wait for debugEvent
        # from target process of debug
        while self.debugger_active == True:
            self.get_debug_event()

    def get_debug_event(self):

        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            
            # # we havnt set eventHandler yet,
            # # so we restart process
            # raw_input("Press a key to continue...")
            # self.debugger_active = False

            # get infomation of thread and context
            self.h_thread = self.open_thread(debug_event.dwThreadId)

            self.context = self.get_thread_context(h_thread=self.h_thread)

            print "Event Code: %d Thread ID: %d" %(debug_event.dwDebugEventCode,
                                                   debug_event.dwThreadId)


            # if Event Code shows exception,
            # chek more
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:

                # check Exception Code
                exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                print exception
                if exception == EXCEPTION_ACCESS_VIOLATION:
                    print "Access Violation Detected."

                # if it is break point,
                # call inside handler
                elif exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()

                elif exception == EXCEPTION_GUARD_PAGE:
                    print "Guard Page Access Detected."

                elif exception == EXCEPTION_SINGLE_STEP:
                    self.exception_handler_single_step()
            
            kernel32.ContinueDebugEvent(
                debug_event.dwProcessId,
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
        snapshot = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPTHREAD, self.pid)
        
        if snapshot is not None:
            # you'l have fault if you set Size of Structure.
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot,
                                             byref(thread_entry))

            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(snapshot,
                                                byref(thread_entry))
                
            kernel32.CloseHandle(snapshot)
            return thread_list
            
        else:
            return False


    def get_thread_context(self, thread_id=None, h_thread=None):

        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        # get handle of thread
        if h_thread is None:
            h_thread = self.open_thread(thread_id)
            
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


    def bp_set_hw(self, address, length, condition):

        # check whether length value is valid
        if length not in (1, 2, 4):
            return False
        else:
            length -= 1

        # check whether condition value is valid
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False

        # check empty resister
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

        # for all resisters, set debug resister.
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            # enable the appropriate flag in DR7
            # resister to set breakpoint
            context.Dr7 |= 1 << (available * 2)

            # set breakpoint to empty resister
            if available == 0:
                context.Dr0 = address
            elif available == 1:
                context.Dr1 = address
            elif available == 2:
                context.Dr2 = address
            elif available == 3:
                context.Dr3 = address

            # set type of breakpoint
            context.Dr7 |= condition << ((available * 4) + 16)

            # set length of breakpoint
            context.Dr7 |= length << ((available * 4) + 18)

            # set threadcontext set with the break set
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

        # update the internal hardware breakpoint array at the used
        # slot index.
        self.hardware_breakpoints[available] = (address, length, condition)

        return True
            

    def bp_set_sw(self, address):
        
        print "[*] Setting breakpoint at: 0x%08x" % address
        if not self.software_breakpoints.has_key(address):
            try:
                # save original byte
                original_byte = self.read_process_memory(address, 1)

                # write opecode INT3
                self.write_process_memory(address, "\xCC")

                # resister breakpoint at indside list
                self.software_breakpoints[address] = (original_byte)
                # print "Succeeded set breakpoint."

            except Exception as e:
                print "[x] Failed to set breakpoint."
                print '[x] Type:' + str(type(e))
                print '[x] Args:' + str(e.args)
                print '[x] Message:' + e.message
                print '[x] Error:' + str(e)
                return False
        return True


    def func_resolve(self, dll, function):

        handle = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, function)
        kernel32.CloseHandle(handle)
        return address

    def exception_handler_single_step(self):

        # Comment from PyDbg:
        # determine if this single step event occuered in reaction to a
        # hardware breakpoint and grab the hit breakpoint.
        # according to the intel docs, we should be able to check for
        # the BS flag in Dr6. but it appears that Windows
        # isnt properly propagating that flag down to us.
        if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
            slot = 0
        elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
            slot = 1
        elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
            slot = 2
        elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
            slot = 3
        else:
            # This wasn't an INT1 genereated by a hw breakpoint.
            continue_status = DBG_EXCEPTION_NOT_HANDLED

        # Now let's remove breakpoint from the list
        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE

        print "[*] hardware brekpoint removed."
        return continue_status


    def bp_del_hw(self, slot):

        # Disable the breakpoint for all active threads
        for thread_id in self.enumerate_threads():

            context = self.get_thread_context(thread_id=thread_id)

            # Reset the flags to remove the breakpoint
            context.Dr7 &= ~(1 << (slot * 2))

            # Zero out the address
            if slot == 0:
                context.Dr0 = 0x00000000
            elif slot == 1:
                context.Dr1 = 0x00000000
            elif slot == 2:
                context.Dr2 = 0x00000000
            elif slot == 3:
                context.Dr3 = 0x00000000

            # Remove the condition flag
            context.Dr7 &= ~(3 << ((slot * 4) + 16))

            # Remove the length flag
            context.Dr7 &= ~(3 << ((slot * 4) + 18))

            # Reset the thread's context with the breakpoint removed
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

        # remove the breakpoint from the internal list.
        del self.hardware_breakpoints[slot]

        return True

    def bp_set_mem(self, address, size):

        mbi = MEMORY_BASIC_INFORMATION()

        # if out VirtualQueryEx() call doesnt return,
        # then, a full-sized MEMORY_BASIC_INFOMATION return False

        if kernel32.VirtualQueryEx(self.h_process,
                                   address,
                                   byref(mbi),
                                   sizeof(mbi)) < sizeof(mbi):
            return False

        current_page = mbi.BaseAddress

        # we will set permissions on all pages that are
        # affected by our memory_breakpoint
        while current_page <= address + size:

            # Add the page to the list; this will
            # diffrentiated our gurded pages from those
            # that were set by the OS or the debuggee process
            self.guarded_pages.append(current_page)

            old_protection = c_ulong(0)
            if not kernel32.VirtualProtectEx(self.h_process,
                                             current_page,
                                             size,
                                             mbi.Protect | PAGE_GUARD,
                                             byref(old_protection)):
                return False

            # add size of default page to current_page size
            current_page += self.page_size

        # add memory breakpoint to global dictionary
        self.memory_breakpoints[address] (size, mbi)

        return True
