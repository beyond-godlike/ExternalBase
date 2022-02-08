#include <Windows.h>
#include <TlHelp32.h> // после windows.h
#include <iostream>
#include <tchar.h>
#include <vector>
#include <stdlib.h>

using namespace std;

uintptr_t GetModuleBaseAddress(TCHAR* lpszModuleName, DWORD pID) {
    uintptr_t dwModuleBaseAddress = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID); // make snapshot of all modules within process
    MODULEENTRY32 ModuleEntry32 = { 0 };
    ModuleEntry32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnapshot, &ModuleEntry32)) //store first Module in ModuleEntry32
    {
        do {
            if (_tcscmp(ModuleEntry32.szModule, lpszModuleName) == 0) // if Found Module matches Module we look for -> done!
            {
                dwModuleBaseAddress = (uintptr_t)ModuleEntry32.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnapshot, &ModuleEntry32)); // go through Module entries in Snapshot and store in ModuleEntry32


    }
    CloseHandle(hSnapshot);
    return dwModuleBaseAddress;
}

DWORD FindDMAAddyEx(HANDLE hProc, DWORD ptr, std::vector<unsigned int> offsets)
{
    for (unsigned int i = 0; i < offsets.size(); ++i)
    {
        ReadProcessMemory(hProc, (BYTE*)ptr, &ptr, sizeof(ptr), 0);
        ptr += offsets[i];
    }
    return ptr;
}
uintptr_t FindDMAAddyEx(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets)
{
    for (unsigned int i = 0; i < offsets.size(); ++i)
    {
        ReadProcessMemory(hProc, (BYTE*)ptr, &ptr, sizeof(ptr), 0);
        ptr += offsets[i];
    }
    return ptr;
}


// mine 
int WriteMem(HANDLE phandle, void* address, int value, size_t sIze, DWORD memProtect) {
    DWORD oldMemProtect = 0;
    VirtualProtectEx(phandle, address, sIze, memProtect, &oldMemProtect);
    WriteProcessMemory(phandle, address, &value, sizeof(value), nullptr);
    VirtualProtectEx(phandle, address, sIze, oldMemProtect, &memProtect);
    return 0;
}


//Internal Pattern Scan
void* PatternScan(char* base, size_t size, const char* pattern, const char* mask)
{
    size_t patternLength = strlen(mask);

    for (unsigned int i = 0; i < size - patternLength; i++)
    {
        bool found = true;
        for (unsigned int j = 0; j < patternLength; j++)
        {
            if (mask[j] != '?' && pattern[j] != *(base + i + j))
            {
                found = false;
                break;
            }
        }
        if (found)
        {
            return (void*)(base + i);
        }
    }
    //cout << "not found " << endl;
    return nullptr;
}

//External Wrapper
void* PatternScanEx(HANDLE hProcess, uintptr_t begin, uintptr_t end, const char* pattern, const char* mask)
{
    uintptr_t currentChunk = begin;
    SIZE_T bytesRead;

    while (currentChunk < end)
    {
        char buffer[4096];

        DWORD oldprotect;
        VirtualProtectEx(hProcess, (void*)currentChunk, sizeof(buffer), PAGE_EXECUTE_READWRITE, &oldprotect);
        ReadProcessMemory(hProcess, (void*)currentChunk, &buffer, sizeof(buffer), &bytesRead);
        VirtualProtectEx(hProcess, (void*)currentChunk, sizeof(buffer), oldprotect, &oldprotect);
        std::cout << buffer << std::endl;

        if (bytesRead == 0)
        {
            return nullptr;
        }

        void* internalAddress = PatternScan((char*)&buffer, bytesRead, pattern, mask);

        if (internalAddress != nullptr)
        {
            //calculate from internal to external
            uintptr_t offsetFromBuffer = (uintptr_t)internalAddress - (uintptr_t)&buffer;
            return (void*)(currentChunk + offsetFromBuffer);
        }
        else
        {
            //advance to next chunk
            currentChunk = currentChunk + bytesRead;
        }
    }
    return nullptr;
}

int main()
{
    HWND hwnd = FindWindowA(NULL, "Dota 2");
    //HWND hwnd = FindWindowA(NULL, "Player");
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


            char gamemodule[] = "engine2.dll";
            //char gamemodule[] = "Player.exe";
            //uintptr_t clientDll = GetModuleBaseAddress(_T(gamemodule), pid);  // многобайтовая кодировка
            uintptr_t engine2Dll = GetModuleBaseAddress(_T(gamemodule), pid);  // многобайтовая кодировка
            //DWORD clientDll = GetModuleBaseAddress(_T(gamemodule), pid);  // многобайтовая кодировка
            cout << std::hex << engine2Dll << endl;

            // адрес куда писать значние
            //DWORD finalAddr = FindDMAAddyEx(phandle, (clientDll + 0x0000C018), { 0x78 });

            //uintptr_t finalAddr = clientDll + 0x375F988;

            int weather;
            int write = 2;
            //ReadProcessMemory(phandle, (LPCVOID)(finalAddr), &weather, sizeof(int), nullptr);
            //cout << std::dec << weather << endl;
      
            //WriteMem(phandle, (void*)finalAddr, write, sizeof(int), PAGE_EXECUTE_READWRITE);
            //ReadProcessMemory(phandle, (LPCVOID)(finalAddr), &weather, sizeof(int), nullptr);
            //cout << std::dec << weather << endl;

            // pattern scanning
            LPCSTR pattern = "\xE8\x00\x00\x00\x00\x33\xD2\x48\x8B\xC7";
            LPCSTR mask = "x????xxxxx";
            uintptr_t end = 0x00007fff35f43000;
            LPVOID PlayerStructBase = PatternScanEx(phandle, engine2Dll, end, pattern, mask);
            cout << std::hex << PlayerStructBase << endl;
        }
    }
    else {
        cout << "Window not found!\n";
    }

    return EXIT_SUCCESS;
}
