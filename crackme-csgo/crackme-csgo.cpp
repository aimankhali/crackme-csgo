#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <sstream>

std::string getHWID()
{
    DWORD volumeSerialNumber = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &volumeSerialNumber, NULL, NULL, NULL, 0);
    std::stringstream ss;
    ss << std::hex << volumeSerialNumber;
    return ss.str();
}

DWORD GetProcessID(const std::wstring& processName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(snapshot, &entry)) {
        do {
            if (!_wcsicmp(entry.szExeFile, processName.c_str())) {
                DWORD pid = entry.th32ProcessID;
                CloseHandle(snapshot);
                return pid;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

bool InjectDLL(DWORD pid, const std::string& dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "OpenProcess failed. Error: " << GetLastError() << "\n";
        return false;
    }

    LPVOID allocMem = VirtualAllocEx(hProcess, nullptr, dllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocMem) {
        std::cout << "VirtualAllocEx failed. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, allocMem, dllPath.c_str(), dllPath.size() + 1, nullptr)) {
        std::cout << "WriteProcessMemory failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get the address of LoadLibraryA
    HMODULE hKernel32 = GetModuleHandleA("Kernel32.dll");
    if (!hKernel32) {
        std::cout << "GetModuleHandleA failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!loadLibraryAddr) {
        std::cout << "GetProcAddress failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocMem, 0, nullptr);

    if (!hThread) {
        std::cout << "CreateRemoteThread failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

int main()
{
    std::string correctHWID = "6d1c088c-d19f-4881-9201-6c59260ca12c";
    std::string systemHWID = getHWID();

    std::cout << "Detected HWID: " << systemHWID << "\n";

    if (systemHWID == correctHWID)
    {
        std::cout << "Access Granted.\n\n";

        std::cout << "Select DLL to inject:\n";
        std::cout << "1: Fatality.dll\n";
        std::cout << "2: OneTap.dll\n";
        std::cout << "3: Airflow.dll\n";
        std::cout << "Enter your choice (1-3): ";

        int choice;
        std::cin >> choice;

        std::string selectedDll;

        switch (choice) {
        case 1:
            selectedDll = "Fatality.dll";
            break;
        case 2:
            selectedDll = "OneTap.dll";
            break;
        case 3:
            selectedDll = "Airflow.dll";
            break;
        default:
            std::cout << "Invalid selection.\n";
            return 1;
        }
        const std::wstring processName = L"csgo.exe";
        DWORD pid = GetProcessID(processName);
        if (pid == 0) {
            std::wcout << L"Process " << processName << L" not found.\n";
            std::system("pause");
            return 1;
        }

        std::cout << "Process csgo.exe found (PID): " << pid << "\n";

        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);

        std::string dllPath = exePath;
        dllPath = dllPath.substr(0, dllPath.find_last_of("\\/")) + "\\" + selectedDll;

        std::cout << "Attempting to inject DLL: " << dllPath << "\n";

        if (InjectDLL(pid, dllPath))
        {
            std::cout << "DLL injected successfully.\n";
            std::system("pause");
        }
        else
        {
            std::cout << "DLL injection failed.\n";
            std::system("pause");
        }
    }

    else
    {
        std::cout << "\n[*] Invalid HWID\n";
    }

    std::system("pause");
    return 0;
}