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

#ifndef DLLINJECT_H
#define DLLINJECT_H

#include <Windows.h>

// Determine whether the program with the specified PID contains a DLL (SPECIFY NAME NOT PATH!)
BOOL DLLIsRunning(_In_ LPTSTR lpDLLName, _In_opt_ DWORD dwPid);

// Inject DLL into the specified PID program
BOOL DLLInject(_In_ LPTSTR lpDLLPath, _In_opt_ DWORD dwPid);

// Uninstall DLL from program with specified PID (SPECIFY NAME NOT PATH!)
BOOL DLLUninject(_In_ LPTSTR lpDLLName, _In_opt_ DWORD dwPid);

#endif