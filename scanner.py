import ctypes
import os
import datetime

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

TH32CS_SNAPPROCESS = 0x00000002

GREEN = "\033[92m"
RESET = "\033[0m"

ctypes.windll.kernel32.SetConsoleTitleW("SS Tool · Made By Shrmpee")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_char * 260),
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]

def find_javaw_pid():
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == -1:
        return None

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if not kernel32.Process32First(snapshot, ctypes.byref(entry)):
        kernel32.CloseHandle(snapshot)
        return None

    while True:
        exe = entry.szExeFile.decode(errors="ignore").lower()
        if exe == "javaw.exe":
            kernel32.CloseHandle(snapshot)
            return entry.th32ProcessID

        if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
            break

    kernel32.CloseHandle(snapshot)
    return None

def scan_process(pid):
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        pid
    )

    if not handle:
        print("Failed to open javaw.exe")
        return

    targets = {
        "https://grimclient.pl": "Grim Client",
        "https://grimclient.eu": "Grim Client",
        "Version: 4.2": "Grim Client (possible)",
        "Grim Client": "Grim Client",
        "https://prestigeclient.vip": "Prestige Client",
        "Voil default": "Voil Client",
        "Safe Anchor": "Generic Client",
        "BYPASSt/config": "22qq Client",
        "Anchor Macro": "Generic Client",
        "Double Anchor": "Generic Client",
        "Auto Crystal": "Generic Client",
        "Auto Hit Crystal": "Generic Client",
        "1275722588265517056": "GrimClient (Image ID)",
    }

    encoded_targets = {k.encode(): v for k, v in targets.items()}

    mbi = MEMORY_BASIC_INFORMATION()
    address = 0

    print(f"Scanning Minecraft (PID {pid})...\n")

    while kernel32.VirtualQueryEx(
        handle,
        ctypes.c_void_p(address),
        ctypes.byref(mbi),
        ctypes.sizeof(mbi)
    ):
        if (
            mbi.State == MEM_COMMIT
            and not (mbi.Protect & PAGE_NOACCESS)
            and not (mbi.Protect & PAGE_GUARD)
        ):
            buffer = ctypes.create_string_buffer(mbi.RegionSize)
            bytes_read = ctypes.c_size_t()

            if kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(address),
                buffer,
                mbi.RegionSize,
                ctypes.byref(bytes_read)
            ):
                data = buffer.raw[:bytes_read.value]

                for sig, label in encoded_targets.items():
                    if sig in data:
                        print(f"{GREEN}[{label} Found]{RESET} '{sig.decode()}' at 0x{address:X}")

        address += mbi.RegionSize

    kernel32.CloseHandle(handle)
    print("\nMemory scan finished.\n")

def scan_prefetch_strings():
    prefetch_dir = r"C:\Windows\Prefetch"
    if not os.path.exists(prefetch_dir):
        return

    prefetch_targets = {
        "GRIMCLIENT": "Grim Client",
        "GRIM": "Grim Client",
        "PRESTIGE": "Prestige Client",
        "METEOR": "Meteor Client",
        "LIQUIDBOUNCE": "LiquidBounce",
        "WURST": "Wurst Client",
        "ARISTOIS": "Aristois Client",
        "PHOBOS": "Phobos Client",
        "RUSHERHACK": "RusherHack",
        "FUTURE": "Future Client",
        "SALHACK": "SalHack"
    }

    print("Scanning Prefetch...\n")

    for file in os.listdir(prefetch_dir):
        upper = file.upper()
        for sig, label in prefetch_targets.items():
            if sig in upper:
                pf_path = os.path.join(prefetch_dir, file)
                # Get last modified time
                last_run = datetime.datetime.fromtimestamp(os.path.getmtime(pf_path))
                print(f"{GREEN}[{label} Prefetch Found]{RESET} '{file}' | Last Run: {last_run}")

if __name__ == "__main__":
    pid = find_javaw_pid()

    if not pid:
        print("javaw.exe not found")
    else:
        scan_process(pid)
        scan_prefetch_strings()  # Prefetch scan now shows last run timestamp
