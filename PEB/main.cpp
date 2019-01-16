#include <iostream>
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
);

int main()
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    for (int i = 0; i < sizeof(si); i++)
    {
        ((unsigned char *)(&si))[i] = 0;
    }
    si.cb = sizeof(si);
    for (int i = 0; i < sizeof(pi); i++)
    {
        ((unsigned char *)(&pi))[i] = 0;
    }
    CREATE_PROCESS_A_PROC create_process_a = (CREATE_PROCESS_A_PROC)InternalGetProcAddress(InternalGetModuleHandleW(L"kernel32.dll"), "CreateProcessA");
    create_process_a("C:\\Windows\\system32\\cmd.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    return 0;
}
