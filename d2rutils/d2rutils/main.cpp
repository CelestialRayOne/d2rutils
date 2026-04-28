// StashSearch injector.
//
// Standalone loader that injects StashSearch.dll into a running D2R.exe.
// Structured as a minimal adaptation of D2RHUD's injector so the injection
// logic is easy to copy-paste into D2RHUD or any similar host later.
//
// Usage: StashSearchInjector.exe "D2R.exe"

#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <vector>
#include <format>
#include <filesystem>
#include <wtsapi32.h>
#include <Psapi.h>

#pragma comment(lib, "Wtsapi32.lib")

// The DLL sits next to the injector. We copy it to a renamed path before
// loading so repeated injections don't fight Windows' "file locked by
// another process" behaviour on the original filename.
#define ORIGINAL_DLL_NAME L"StashSearch.dll"
#define RENAMED_DLL_NAME  L"stashsearchb.dll"

static std::wstring ExePath();
static std::vector<DWORD> GetPIDs(std::wstring processName);
static void EjectDLL(int pid, const std::wstring& moduleName);
static void InjectDLL(int pid, const std::wstring& path);

int main(int argc, char* /*argv*/[])
{
    if (argc != 2) {
        std::wcerr << L"Usage: StashSearchInjector.exe \"D2R.exe\"" << std::endl;
        return -1;
    }

    int wargc = 0;
    wchar_t** wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    std::wcout << L"[+] Target process: " << wargv[1] << std::endl;

    std::vector<DWORD> pids = GetPIDs(wargv[1]);
    if (pids.empty()) {
        std::wcerr << L"[!] No matching processes found." << std::endl;
        return -2;
    }

    for (DWORD pid : pids) {
        std::wstring originalDllPath = std::format(L"{}\\{}", ExePath(), ORIGINAL_DLL_NAME);
        std::wstring dllPath = std::format(L"{}\\{}", ExePath(), RENAMED_DLL_NAME);

        std::wcout << L"[+] Injecting into PID " << pid << std::endl;

        EjectDLL(static_cast<int>(pid), RENAMED_DLL_NAME);

        std::error_code ec;
        std::filesystem::copy(originalDllPath, dllPath,
            std::filesystem::copy_options::update_existing, ec);
        if (ec) {
            std::wcerr << L"[!] Failed to stage DLL copy: " << ec.value() << std::endl;
            continue;
        }

        InjectDLL(static_cast<int>(pid), dllPath);
    }

    return 0;
}

static std::wstring ExePath() {
    wchar_t buffer[MAX_PATH] = { 0 };
    GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    std::wstring full(buffer);
    auto pos = full.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? full : full.substr(0, pos);
}

static std::vector<DWORD> GetPIDs(std::wstring processName) {
    std::vector<DWORD> pids;
    WTS_PROCESS_INFOW* pWPIs = nullptr;
    DWORD dwProcCount = 0;
    if (WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pWPIs, &dwProcCount)) {
        for (DWORD i = 0; i < dwProcCount; ++i) {
            if (pWPIs[i].pProcessName && !wcscmp(pWPIs[i].pProcessName, processName.c_str())) {
                pids.push_back(pWPIs[i].ProcessId);
            }
        }
    }
    if (pWPIs) WTSFreeMemory(pWPIs);
    return pids;
}

static void EjectDLL(int pid, const std::wstring& moduleName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    bool found = false;
    if (Module32FirstW(hSnapshot, &entry)) {
        do {
            if (!_wcsicmp(entry.szModule, moduleName.c_str())) {
                found = true;
                break;
            }
        } while (Module32NextW(hSnapshot, &entry));
    }
    CloseHandle(hSnapshot);

    if (!found) return;

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE, pid);
    if (!hProc) return;

    std::wcout << L"[+] DLL already present; ejecting first." << std::endl;

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID  freeLibrary = reinterpret_cast<LPVOID>(GetProcAddress(hKernel32, "FreeLibrary"));
    if (freeLibrary) {
        HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(freeLibrary),
            entry.modBaseAddr, 0, nullptr);
        if (hThread) {
            WaitForSingleObject(hThread, 5000);
            CloseHandle(hThread);
        }
    }
    CloseHandle(hProc);
}

static void InjectDLL(int pid, const std::wstring& path) {
    if (!std::filesystem::exists(path)) {
        std::wcerr << L"[!] DLL not found: " << path << std::endl;
        return;
    }

    const SIZE_T dllPathSize = (path.length() + 1) * sizeof(wchar_t);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        std::wcerr << L"[!] OpenProcess failed. GLE=" << GetLastError() << std::endl;
        return;
    }

    LPVOID pRemotePath = VirtualAllocEx(hProc, nullptr, dllPathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemotePath) {
        std::wcerr << L"[!] VirtualAllocEx failed. GLE=" << GetLastError() << std::endl;
        CloseHandle(hProc);
        return;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, pRemotePath, path.c_str(), dllPathSize, &written) ||
        written != dllPathSize) {
        std::wcerr << L"[!] WriteProcessMemory failed. GLE=" << GetLastError() << std::endl;
        VirtualFreeEx(hProc, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return;
    }

    // Verify what we wrote landed correctly.
    std::vector<wchar_t> readback(path.length() + 1);
    SIZE_T readBytes = 0;
    ReadProcessMemory(hProc, pRemotePath, readback.data(), dllPathSize, &readBytes);
    std::wcout << L"[+] Remote path readback: \"" << readback.data() << L"\"" << std::endl;

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID  pLoadLibrary = reinterpret_cast<LPVOID>(GetProcAddress(hKernel32, "LoadLibraryW"));

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibrary),
        pRemotePath, 0, nullptr);
    if (!hThread) {
        std::wcerr << L"[!] CreateRemoteThread failed. GLE=" << GetLastError() << std::endl;
        VirtualFreeEx(hProc, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return;
    }

    WaitForSingleObject(hThread, 10 * 1000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    std::wcout << L"[+] LoadLibraryW returned: 0x" << std::hex << exitCode << std::dec << std::endl;

    if (exitCode == 0) {
        // Call GetLastError inside the remote process.
        LPVOID pGetLastError = reinterpret_cast<LPVOID>(GetProcAddress(hKernel32, "GetLastError"));
        HANDLE hErrThread = CreateRemoteThread(hProc, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(pGetLastError),
            nullptr, 0, nullptr);
        if (hErrThread) {
            WaitForSingleObject(hErrThread, 5000);
            DWORD remoteErr = 0;
            GetExitCodeThread(hErrThread, &remoteErr);
            CloseHandle(hErrThread);

            wchar_t errMsg[512] = {};
            FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, remoteErr,
                0, errMsg, 511, nullptr);
            std::wcerr << L"[!] Remote GetLastError = " << remoteErr
                << L" (" << errMsg << L")" << std::endl;
        }
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProc, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hProc);
}