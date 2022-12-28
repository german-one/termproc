/*
Copyright (c) 2022 Steffen Illhardt

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// Min. req.: C99

#if defined(NDEBUG) && defined(__clang__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wreserved-macro-identifier"
#endif
#undef _CRTBLD
#define _CRTBLD 1
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#if defined(NDEBUG) && defined(__clang__)
#  pragma GCC diagnostic pop
#endif
#undef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>
#include <stddef.h>

// Get the process ID of the terminal connected to the current console application.
// Only Windows Terminal and Conhost are supported.
// Return:
//  If the terminal is Windows Terminal, the PID of the belonging Windows Terminal instance will be returned.
//  If the terminal is Conhost, the PID of the console application that spawned the Conhost instance will be returned.
//  If the function fails, 0 will be returned.
DWORD GetTermPid(void);

// Get the name of the terminal process.
// Parameter:
//  termPid  Process ID returned by GetTermPid().
// Return:
//  Pointer to a static buffer containing the name of the terminal process.
//  If the terminal is Windows Terminal, "WindowsTerminal" will be returned.
//  If the terminal is Conhost, the name of the console application that spawned the Conhost instance will be returned.
//  If the function fails, a zero-length string will be returned.
wchar_t *GetTermBaseName(const DWORD termPid);

// Get the window handle of the terminal's main window.
// Parameter:
//  termPid  Process ID returned by GetTermPid().
// Return:
//  Window handle of the terminal's main window.
//  If the function fails, NULL will be returned.
HWND GetTermWnd(const DWORD termPid);

typedef enum
{
  FadeOut,
  FadeIn
} FadeMode;

// for fading out or fading in a window, used to prove that we found the right terminal process
void Fade(const HWND hWnd, const FadeMode mode);

#include <stdio.h>

#if defined(NDEBUG) && defined(__clang__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#endif

int main(void)
{
  const DWORD termPid = GetTermPid();
  if (!termPid)
    return 1;

  const HWND termWnd = GetTermWnd(termPid);
  wprintf(L"Term proc: %s\nTerm PID:  %lu\nTerm HWND: %08zX\n", GetTermBaseName(termPid), termPid, (UINT_PTR)(void *)termWnd);

  Fade(termWnd, FadeOut);
  Fade(termWnd, FadeIn);
  return 0;
}

#if defined(NDEBUG) && defined(__clang__)
#  pragma GCC diagnostic pop
#endif

#include <SubAuth.h>
#include <stdbool.h>
#include <stdint.h>
#include <wchar.h>

#ifdef NDEBUG
#  if defined(__GNUC__) || defined(__clang__)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wcast-align"
#    pragma GCC diagnostic ignored "-Wcast-function-type"
#    pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#  elif defined(_MSC_VER)
#    pragma warning(push)
#    pragma warning(                                                                                   \
      disable : 4191 /* unsafe conversion (function types) */                                          \
      4706 /* assignment within conditional expression */                                              \
      4710 /* function not inline */                                                                   \
      4711 /* function selected for inline expansion */                                                \
      4820 /* padding added */                                                                         \
      5045 /* compiler will insert Spectre mitigation for memory load if /Qspectre switch specified */ \
    )
#  endif
#endif

// Get the name of the process from the process handle.
// Returns a pointer to a static buffer containing the name of the process.
// If the function fails, a zero-length string will be returned.
static wchar_t *GetProcBaseName(const HANDLE hProc)
{
  static wchar_t baseBuf[MAX_PATH] = { 0 };
  *baseBuf = L'\0';
  if (!hProc)
    return baseBuf;

  wchar_t nameBuf[1024] = { 0 };
  DWORD size = 1024;
  if (QueryFullProcessImageNameW(hProc, 0, nameBuf, &size))
    _wsplitpath_s(nameBuf, NULL, 0, NULL, 0, baseBuf, MAX_PATH, NULL, 0);

  return baseBuf;
}

// undocumented SYSTEM_HANDLE structure, SYSTEM_HANDLE_TABLE_ENTRY_INFO might be the actual name
typedef struct
{
  const DWORD ProcId; // PID of the process the SYSTEM_HANDLE belongs to
  const BYTE ObjTypeId; // identifier of the object
  const BYTE Flgs;
  const WORD Handle; // value representing an opened handle in the process
  const PVOID pObj;
  const DWORD Acc;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

// Enumerate the opened handles in each process, select those that refer to the same process as findOpenProcId.
// Return the ID of the process that opened the handle if its name is the same as searchProcName,
// Return 0 if no such process is found.
static DWORD GetPidOfNamedProcWithOpenProcHandle(const wchar_t *const searchProcName, const DWORD findOpenProcId)
{
  typedef NTSTATUS(__stdcall * NtQuerySystemInformation_t)(int SysInfClass, PVOID SysInf, DWORD SysInfLen, PDWORD RetLen);
  typedef BOOL(__stdcall * CompareObjectHandles_t)(HANDLE hFirst, HANDLE hSecond);

  static const NTSTATUS STATUS_INFO_LENGTH_MISMATCH = (NTSTATUS)0xc0000004; // NTSTATUS returned if we still didn't allocate enough memory
  static const int SystemHandleInformation = 16; // one of the SYSTEM_INFORMATION_CLASS values
  static const BYTE OB_TYPE_INDEX_JOB = 7; // one of the SYSTEM_HANDLE.ObjTypeId values

  NtQuerySystemInformation_t NtQuerySystemInformation;
  CompareObjectHandles_t CompareObjectHandles;

  HMODULE hModule = GetModuleHandleA("ntdll.dll");
  if (!hModule || !(NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hModule, "NtQuerySystemInformation")))
    return 0;

  hModule = GetModuleHandleA("kernelbase.dll");
  if (!hModule || !(CompareObjectHandles = (CompareObjectHandles_t)GetProcAddress(hModule, "CompareObjectHandles")))
    return 0;

  // allocate some memory representing an undocumented SYSTEM_HANDLE_INFORMATION object, which can't be meaningfully declared in C# code
  DWORD infSize = 0x200000;
  PBYTE pSysHndlInf = GlobalAlloc(GMEM_FIXED, infSize);
  if (!pSysHndlInf)
    return 0;

  DWORD len;
  NTSTATUS status;
  // try to get an array of all available SYSTEM_HANDLE objects, allocate more memory if necessary
  while ((status = NtQuerySystemInformation(SystemHandleInformation, (PVOID)pSysHndlInf, infSize, &len)) == STATUS_INFO_LENGTH_MISMATCH)
  {
    GlobalFree(pSysHndlInf);
    infSize = len + 0x1000;
    pSysHndlInf = GlobalAlloc(GMEM_FIXED, infSize);
    if (!pSysHndlInf)
      return 0;
  }

  HANDLE hFindOpenProc;
  if (!NT_SUCCESS(status) ||
      !(hFindOpenProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, findOpenProcId))) // intentionally after NtQuerySystemInformation() was called to exclude it from the found open handles
  {
    GlobalFree(pSysHndlInf);
    return 0;
  }

  const HANDLE hThis = GetCurrentProcess();
  DWORD curPid = 0, foundPid = 0;
  HANDLE hCur = NULL;
  // iterate over the array of SYSTEM_HANDLE objects, which begins at an offset of pointer size in the SYSTEM_HANDLE_INFORMATION object
  // the number of SYSTEM_HANDLE objects is specified in the first 32 bits of the SYSTEM_HANDLE_INFORMATION object
  for (const SYSTEM_HANDLE *pSysHndl = (PSYSTEM_HANDLE)(pSysHndlInf + sizeof(intptr_t)),
                           *const pEnd = pSysHndl + *(DWORD *)pSysHndlInf;
       !foundPid && pSysHndl < pEnd;
       ++pSysHndl)
  {
    // shortcut; OB_TYPE_INDEX_JOB is the identifier we are looking for, any other SYSTEM_HANDLE object is immediately ignored at this point
    if (pSysHndl->ObjTypeId != OB_TYPE_INDEX_JOB)
      continue;

    // every time the process changes, the previous handle needs to be closed and we open a new handle to the current process
    if (curPid != pSysHndl->ProcId)
    {
      curPid = pSysHndl->ProcId;
      if (hCur)
        CloseHandle(hCur);

      hCur = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, curPid);
    }

    HANDLE hCurOpenDup;
    // if the process has not been opened, or
    // if duplicating the current one of its open handles fails, continue with the next SYSTEM_HANDLE object
    // the duplicated handle is necessary to get information about the object (e.g. the process) it points to
    if (!hCur ||
        !DuplicateHandle(hCur, (HANDLE)(intptr_t)pSysHndl->Handle, hThis, &hCurOpenDup, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0))
      continue;

    if (CompareObjectHandles(hCurOpenDup, hFindOpenProc) && // both the handle of the open process and the currently duplicated handle must refer to the same kernel object
        0 == lstrcmpW(GetProcBaseName(hCur), searchProcName)) // the process name of the currently found process must meet the process name we are looking for
      foundPid = curPid;

    CloseHandle(hCurOpenDup);
  }

  if (hCur)
    CloseHandle(hCur);

  GlobalFree(pSysHndlInf);
  CloseHandle(hFindOpenProc);
  return foundPid;
}

DWORD GetTermPid(void)
{
  static bool isDetermined = false;
  static DWORD termPid = 0;
  // Skip the long-winded code, the PID needs to be determined only once.
  if (isDetermined)
    return termPid;

  isDetermined = true;
  const HWND conWnd = GetConsoleWindow();
  DWORD shellPid = 0;
  // Get the ID of the Shell process that spawned the Conhost process.
  GetWindowThreadProcessId(conWnd, &shellPid);
  // We don't have a proper way to figure out to what terminal app the Shell process
  // is connected on the local machine:
  // https://github.com/microsoft/terminal/issues/7434
  // We're getting around this assuming we don't get an icon handle from the
  // invisible Conhost window when the Shell is connected to Windows Terminal.
  if (SendMessageW(conWnd, WM_GETICON, 0, 0))
  {
    // Conhost assumed: The Shell process' main window is the console window.
    // (weird because the Shell has no own window, but it has always been like this)
    return (termPid = shellPid);
  }

  return (termPid = GetPidOfNamedProcWithOpenProcHandle(L"WindowsTerminal", shellPid));
}

wchar_t *GetTermBaseName(const DWORD termPid)
{
  const HANDLE hTerm = termPid ? OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, termPid) : NULL;
  wchar_t *const baseName = GetProcBaseName(hTerm);
  if (hTerm)
    CloseHandle(hTerm);

  return baseName;
}

typedef struct
{
  const DWORD pid;
  HWND hWnd;
} WND_CALLBACK_DAT, *PWND_CALLBACK_DAT;

static BOOL __stdcall GetTermWndCallback(HWND hWnd, LPARAM lParam)
{
  const PWND_CALLBACK_DAT pSearchDat = (PWND_CALLBACK_DAT)lParam;
  DWORD pid = 0;
  GetWindowThreadProcessId(hWnd, &pid);
  if (pid != pSearchDat->pid || !IsWindowVisible(hWnd) || GetWindow(hWnd, GW_OWNER))
    return TRUE;

  pSearchDat->hWnd = hWnd;
  return FALSE;
}

HWND GetTermWnd(const DWORD termPid)
{
  if (!termPid)
    return NULL;

  WND_CALLBACK_DAT searchDat = { termPid, NULL };
  EnumWindows(GetTermWndCallback, (LPARAM)&searchDat);
  return searchDat.hWnd;
}

void Fade(const HWND hWnd, const FadeMode mode)
{
  SetWindowLongW(hWnd, GWL_EXSTYLE, GetWindowLongW(hWnd, GWL_EXSTYLE) | WS_EX_LAYERED);

  if (mode == FadeOut)
  {
    for (int alpha = 255; alpha >= 0; alpha -= 3)
    {
      SetLayeredWindowAttributes(hWnd, 0, (BYTE)alpha, LWA_ALPHA);
      Sleep(1);
    }

    return;
  }

  for (int alpha = 0; alpha <= 255; alpha += 3)
  {
    SetLayeredWindowAttributes(hWnd, 0, (BYTE)alpha, LWA_ALPHA);
    Sleep(1);
  }
}

#ifdef NDEBUG
#  if defined(__GNUC__) || defined(__clang__)
#    pragma GCC diagnostic pop
#  elif defined(_MSC_VER)
#    pragma warning(pop)
#  endif
#endif
