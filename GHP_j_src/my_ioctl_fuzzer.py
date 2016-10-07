import pickle
import sys
import random

from ctypes import *

kernel32 = windll.kernel32

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 0x3

fd = open(sys.argv[1], "rb")
master_list = pickle.load(fd)
ioctl_list = master_list["ioctl_list"]
device_list = master_list["device_list"]
fd.close()

valid_devices = []

for device_name in device_list:
    device_file = u"\\\\.\\%s" % device_name.split("\\")[::-1][0]
    print "[*] Testing for device: %s" % device_file

    driver_handle = kernel32.CreateFileW(device_file, GENERIC_READ | GENERIC_WRITE,
                                         0, None, OPEN_EXISTING, 0, None)

    if driver_handle:
        print "[*] Success! %s is a valid device!" % device_name

        if device_file not in valid_devices:
            valid_devices.append(device_file)

        kernel32.CloseHandle(driver_handle)
    else:
        print "[*] Failed! %s is NOT a valid device." % device_name

if not len(valid_devices):
    print "[*] No valid devices found. Exiting..."
    sys.exit(0)

while 1:
    fd = open("my_ioctl_fuzzer.log", "a")

    current_device = valid_devices[random.randint(0, len(valid_devices)-1)]
    fd.write("[*] Fuzzing: %s\n" % current_device)

    current_ioctl = ioctl_list[random.randint(0, len(ioctl_list)-1)]
    fd.write("[*] With IOCTL: 0x%08x\n" % current_ioctl)

    current_length = random.randint(0, 10000)
    fd.write("[*] Buffer length: %d\n" % current_length)

    in_buffer = "A" * current_length
    out_buf = (c_char * current_length)()
    bytes_returned = c_ulong(current_length)

    driver_handle = kernel32.CreateFileW(device_file, GENERIC_READ | GENERIC_WRITE,
                                         0, None, OPEN_EXISTING, 0, None)

    fd.write("!!FUZZ!!\n")
    kernel32.DeviceIoControl(driver_handle, current_ioctl, in_buffer, current_length,
                             byref(out_buf), current_length, byref(bytes_returned), None)
    fd.write("[*] Test case finished. %d bytes returned.\n\n" % bytes_returned.value)

    kernel32.CloseHandle(driver_handle)
    fd.close()
