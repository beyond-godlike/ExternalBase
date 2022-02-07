#include <Windows.h>
#include <TlHelp32.h> // после windows.h
#include <iostream>
#include <tchar.h>
#include <vector>
#include <stdlib.h>

using namespace std;

DWORD GetModuleBaseAddress(TCHAR* lpszModuleName, DWORD pID) {
    DWORD dwModuleBaseAddress = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID); // make snapshot of all modules within process
    MODULEENTRY32 ModuleEntry32 = { 0 };
    ModuleEntry32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnapshot, &ModuleEntry32)) //store first Module in ModuleEntry32
    {
        do {
            if (_tcscmp(ModuleEntry32.szModule, lpszModuleName) == 0) // if Found Module matches Module we look for -> done!
            {
                dwModuleBaseAddress = (DWORD)ModuleEntry32.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnapshot, &ModuleEntry32)); // go through Module entries in Snapshot and store in ModuleEntry32


    }
    CloseHandle(hSnapshot);
    return dwModuleBaseAddress;
}

uintptr_t FindDMAAddy(uintptr_t ptr, std::vector<unsigned int> offsets)
{
    uintptr_t addr = ptr;
    for (unsigned int i = 0; i < offsets.size(); ++i)
    {
        addr = *(uintptr_t*)addr;
        addr += offsets[i];
    }
    return addr;
}


// mine 
int WriteMem(HANDLE phandle, void* address, int value, size_t sIze, DWORD memProtect) {
    DWORD oldMemProtect = 0;
    VirtualProtectEx(phandle, address, sIze, memProtect, &oldMemProtect);
    WriteProcessMemory(phandle, address, &value, sizeof(value), nullptr);
    VirtualProtectEx(phandle, address, sIze, oldMemProtect, &memProtect);
    return 0;
}

int main()
{
    HWND hwnd = FindWindowA(NULL, "Dota 2");
    if (hwnd != NULL) {
        cout << "Window found!\n";

        DWORD pid = NULL;
        GetWindowThreadProcessId(hwnd, &pid);
        cout << pid << endl;
        HANDLE phandle = NULL;
        phandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (phandle == INVALID_HANDLE_VALUE || phandle == NULL) { // от администратора
            cout << "No phandle";
        }
        else {
            // get base of client.dll
            cout << "Success!" << endl;


            //char gamemodule[] = "cheatengine-x86_64.exe";
            char gamemodule[] = "client.dll";
            DWORD clientDll = GetModuleBaseAddress(_T(gamemodule), pid);  // многобайтовая кодировка
            cout << std::hex << clientDll << endl;

            // адрес куда писать значние
            //client.dll+375F988
            //uintptr_t finalAddr = FindDMAAddy(static_cast<uintptr_t>(clientDll) + 0x03752868, { 0xFF8 });
           DWORD finalAddr = clientDll + 0x375F988;

            int weather;
            ReadProcessMemory(phandle, (LPCVOID)(finalAddr), &weather, sizeof(int), nullptr);
            cout << std::hex << weather << endl;
      
            WriteMem(phandle, (void*)finalAddr, 9, sizeof(int), PAGE_EXECUTE_READWRITE);
            ReadProcessMemory(phandle, (LPCVOID)(finalAddr), &weather, sizeof(int), nullptr);
            cout << std::hex << weather << endl;
        }
    }
    else {
        cout << "Window not found!\n";
    }

    return EXIT_SUCCESS;
}
