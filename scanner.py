import ctypes
import subprocess

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

TH32CS_SNAPPROCESS = 0x00000002

RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

os.system('cls' if os.name == 'nt' else 'clear')
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

def get_exe_name(pid):
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return "Unknown"

    exe_name_buffer = ctypes.create_string_buffer(260)
    size = ctypes.c_uint(260)
    psapi = ctypes.WinDLL("Psapi")
    psapi.GetModuleFileNameExA(handle, 0, exe_name_buffer, size)
    kernel32.CloseHandle(handle)
    return exe_name_buffer.value.decode(errors="ignore").split("\\")[-1]

def scan_process(pid):
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        pid
    )

    if not handle:
        print("Failed to open process")
        return

    exe_name = get_exe_name(pid)

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
        "Double Anchor": "Generic Client"
        "Kill Aura": "Generic Client",
        "Self Destruct": "Generic Client",
        "Aim Assist": "Generic Client",
        "Argon": "Argon",
        "LiquidBounce": "LiquidBounce",
        "Krypton+": "Krypton",
        "Krypton": "Krypton",
        "Auto Crystal": "Generic Client",
        "Auto Hit Crystal": "Generic Client",
        "1275722588265517056": "Grim Client (Image ID)",
        "S2lsbCBBdXJh": "KillAura (Base64 Encoded)"
        "UmVhY2g=": "Reach (Base64 Encoded)"
        "VHJpZ2dlciBCb3Q=": "TriggerBot (Base64 Encoded)"
        "QXV0byBDcml0cw==": "AutoCrit (Base64 Encoded)"
        "U3BlZWQ=": "Speed (Base64 Encoded)",
        "Rmx5": "Fly (Base64 Encoded)",
        "Tm9GYWxs": "NoFall (Base64 Encoded)",
        "UGhhc2U=": "Phase (Base64 Encoded)",
        "V2FsbGhhY2s=": "Wallhack (Base64 Encoded)",
        "QmxvY2sgRVNQ": "BlockESP (Base64 Encoded)",
        "UGxheWVyIEVTUA==": "PlayerESP (Base64 Encoded)",
        "VHJhY2Vycw==": "Tracers (Base64 Encoded)",
        "SGVhbHRoIEVTUA==": "HealthESP (Base64 Encoded)",
        "QXJtb3IgRVNQ": "ArmorESP (Base64 Encoded)",
        "Q2hlc3QgRVNQ": "ChestESP (Base64 Encoded)",
        "SXRlbSBFU1A=": "ItemESP (Base64 Encoded)",
        "QXV0byBBcm1vcg==": "AutoArmor (Base64 Encoded)",
        "SW52ZW50b3J5IE1hbmFnZXI=": "InvManager (Base64 Encoded)",
        "QW50aUtC": "AntiKB (Base64 Encoded)",
        "QXV0byBTd29yZA==": "AutoSword (Base64 Encoded)",
        "V2VhcG9uIFN3aXRjaGVy": "WeaponSwitch (Base64 Encoded)",
        "Q3JpdGljYWxz": "Criticals (Base64 Encoded)",
        "S3J5cHRvbg==": "Krypton (Base64 Encoded)",
        "V2Vyc3Q=": "Wurst (Base64 Encoded)",
        "SW1wYWN0": "Impact (Base64 Encoded)",

    }

    encoded_targets = {k.encode(): v for k, v in targets.items()}

    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    reported_signatures = set()  # Track unique signatures to prevent duplicates

    print(f"Scanning {GREEN}{exe_name}{RESET} (PID {pid})...\n")

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
                    if sig in data and sig not in reported_signatures:
                        print(f"{RED}[{label} Found]{RESET} '{sig.decode()}' at 0x{address:X}")
                        reported_signatures.add(sig)

        address += mbi.RegionSize

    kernel32.CloseHandle(handle)
    print("\nMemory scan finished.\n")

def prompt_habibi_scan():
    choice = input(f"Scan With Habibi (y/n): ").strip().lower()
    if choice == "y":
        ctypes.windll.kernel32.SetConsoleTitleW(
            "SS Tool · Made By Shrmpee · Credit to Habibi"
        )
        print("\nRunning Habibi scan...\n")
        ps_command = (
            'Set-ExecutionPolicy Bypass -Scope Process; '
            'Invoke-Expression (Invoke-RestMethod '
            '"https://raw.githubusercontent.com/HadronCollision/'
            'PowershellScripts/refs/heads/main/HabibiModAnalyzer.ps1")'
        )
        try:
            subprocess.run(["powershell", "-Command", ps_command], check=True)
            print("\nHabibi scan completed.\n")
        except subprocess.CalledProcessError as e:
            print(f"\nHabibi scan failed: {e}\n")
    else:
        print("\nSkipped Habibi scan.\n")

if __name__ == "__main__":
    pid = find_javaw_pid()

    if not pid:
        print("javaw.exe not found")
    else:
        scan_process(pid)
        prompt_habibi_scan()
