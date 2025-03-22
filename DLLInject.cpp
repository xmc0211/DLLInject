// MIT License
//
// Copyright (c) 2025 DLLInject - xmc0211 <xmc0211@qq.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "DLLInject.h"
#include <TlHelp32.h>
#include <tchar.h>

BOOL DLLIsRunning(_In_ LPTSTR lpDLLName, _In_opt_ DWORD dwPid) {
    MODULEENTRY32 ModuleEnt;
    BOOL bFound = FALSE;

    // 获取加载的所有DLL，并挨个比较
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    ModuleEnt.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hSnapshot, &ModuleEnt)) {
        CloseHandle(hSnapshot);
        return FALSE;
    }
    do {
        if (_tcscmp(ModuleEnt.szModule, lpDLLName) == 0) {
            bFound = TRUE;
            break;
        }
    } while (Module32Next(hSnapshot, &ModuleEnt));
    CloseHandle(hSnapshot);
    return bFound;
}

BOOL DLLInject(_In_ LPTSTR lpDLLPath, _In_opt_ DWORD dwPid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess) return FALSE;

    // 在进程中分配内存
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, _tcslen(lpDLLPath) * sizeof(TCHAR) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMemory) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 写入DLL路径
    BOOL success = WriteProcessMemory(hProcess, pRemoteMemory, lpDLLPath, _tcslen(lpDLLPath) * sizeof(TCHAR) + 1, NULL);
    if (!success) {
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    // 创建远程线程加载DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, pRemoteMemory, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 等待线程结束
    WaitForSingleObject(hThread, INFINITE);

    // 清理
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}

BOOL DLLUninject(_In_ LPTSTR lpDLLName, _In_opt_ DWORD dwPid) {
    MODULEENTRY32 ModuleEnt;
    BOOL bFound = FALSE;

    // 避免误卸载其它DLL
    if (!DLLIsRunning(lpDLLName, dwPid)) return FALSE;

    ModuleEnt.dwSize = sizeof(MODULEENTRY32);
    // 获取加载的所有DLL，并挨个比较
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    if (!Module32First(hSnapshot, &ModuleEnt)) {
        CloseHandle(hSnapshot);
        return FALSE;
    }
    do {
        if (_tcscmp(ModuleEnt.szModule, lpDLLName) == 0) break;
    } while (Module32Next(hSnapshot, &ModuleEnt));

    // 获取目标进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess) {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    // 获取 FreeLibrary 地址
    HMODULE hMod = GetModuleHandle(TEXT("Kernel32.dll"));
    if (hMod == NULL) {
        CloseHandle(hProcess);
        CloseHandle(hSnapshot);
        return FALSE;
    }
    LPTHREAD_START_ROUTINE pThread = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "FreeLibrary");
    if (pThread == NULL) {
        CloseHandle(hProcess);
        CloseHandle(hSnapshot);
        return FALSE;
    }

    // 调用 FreeLibrary 卸载DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pThread, ModuleEnt.modBaseAddr, 0, NULL);
    if (!hThread) {
        CloseHandle(hProcess);
        CloseHandle(hSnapshot);
        return FALSE;
    }

    // 等待线程结束
    WaitForSingleObject(hThread, INFINITE);

    // 清理
    CloseHandle(hThread);
    CloseHandle(hProcess);
    CloseHandle(hSnapshot);
    return TRUE;
}

