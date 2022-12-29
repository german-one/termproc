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

// Min. req.: C++20

#if defined(NDEBUG) && defined(__clang__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wreserved-macro-identifier"
#endif
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#if defined(NDEBUG) && defined(__clang__)
#  pragma GCC diagnostic pop
#endif
#undef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>
#include <cstdint>
#include <string>

#if defined(NDEBUG) && defined(__clang__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wc++98-compat" /* noexcept */
#endif

namespace termproc
{
  namespace termpid
  {
    // Get the process ID of the terminal connected to the current console application.
    // Only Windows Terminal and Conhost are supported.
    // Return:
    //  If the terminal is Windows Terminal, the PID of the belonging Windows Terminal instance will be returned.
    //  If the terminal is Conhost, the PID of the console application that spawned the Conhost instance will be returned.
    //  If the function fails, 0 will be returned.
    DWORD GetTermPid();
  }

  namespace termname
  {
    // Get the name of the terminal process.
    // Parameter:
    //  termPid  Process ID returned by GetTermPid().
    // Return:
    //  A std::wstring containing the name of the terminal process.
    //  If the terminal is Windows Terminal, "WindowsTerminal" will be returned.
    //  If the terminal is Conhost, the name of the console application that spawned the Conhost instance will be returned.
    //  If the function fails, a zero-length string will be returned.
    std::wstring GetTermBaseName(const DWORD termPid);
  }

  namespace termwnd
  {
    // Get the window handle of the terminal's main window.
    // Parameter:
    //  termPid  Process ID returned by GetTermPid().
    // Return:
    //  Window handle of the terminal's main window.
    //  If the function fails, nullptr will be returned.
    HWND GetTermWnd(const DWORD termPid) noexcept;
  }
}

namespace test
{
  enum class FadeMode
  {
    Out,
    In
  };

  // for fading out or fading in a window, used to prove that we found the right terminal process
  void Fade(const HWND hWnd, const FadeMode mode) noexcept;
}

#if defined(NDEBUG) && defined(__clang__)
#  pragma GCC diagnostic pop
#endif

#include <iomanip>
#include <iostream>

#ifdef NDEBUG
#  if defined(__clang__)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wc++98-compat"
#  elif defined(_MSC_VER)
#    pragma warning(push)
#    pragma warning(disable : 26490) /* don't use reinterpret_cast */
#  endif
#endif

int main()
{
  try
  {
    const auto termPid{ termproc::termpid::GetTermPid() };
    if (!termPid)
      return 1;

    const auto termWnd{ termproc::termwnd::GetTermWnd(termPid) };
    std::wcout << L"Term proc: " << termproc::termname::GetTermBaseName(termPid)
               << L"\nTerm PID:  " << termPid
               << L"\nTerm HWND: " << std::setfill(L'0') << std::setw(8) << std::right << std::uppercase << std::hex << reinterpret_cast<intptr_t>(termWnd) << std::endl;

    test::Fade(termWnd, test::FadeMode::Out);
    test::Fade(termWnd, test::FadeMode::In);

    return 0;
  }
  catch (...)
  {
    return 1;
  }
}

#ifdef NDEBUG
#  if defined(__clang__)
#    pragma GCC diagnostic pop
#  elif defined(_MSC_VER)
#    pragma warning(pop)
#  endif
#endif

#include <SubAuth.h>
#include <array>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#ifdef NDEBUG
#  if defined(__GNUC__) || defined(__clang__)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wcast-function-type"
#    if defined(__clang__)
#      pragma GCC diagnostic ignored "-Wc++98-compat"
#      pragma GCC diagnostic ignored "-Wpre-c++17-compat"
#    endif
#  elif defined(_MSC_VER)
#    pragma warning(push)
#    pragma warning(                                                        \
      disable : 4191 /* unsafe conversion (function types) */               \
      4623 /* default constructor was implicitly defined as deleted */      \
      4626 /* assignment operator was implicitly defined as deleted */      \
      4706 /* assignment within conditional expression */                   \
      4710 /* function not inlined */                                       \
      4711 /* function selected for inline expansion */                     \
      4820 /* padding added */                                              \
      5027 /* move assignment operator was implicitly defined as deleted */ \
      5264 /* 'const' variable is not used */                               \
      26472 /* don't use a static_cast for arithmetic conversions */        \
      26481 /* don't use pointer arithmetic */                              \
      26490 /* don't use reinterpret_cast */                                \
    )
#  endif
#endif

namespace saferes
{
  namespace detail
  {
    // having these in a "detail" namespace may protect you from using the ctors directly because there's a high risk for omitting the deleter as second argument
    // use the Make... lambdas (along with the auto keyword for variable declarations)
    constexpr inline auto HandleDeleter{ [](const HANDLE hndl) noexcept { if (hndl && hndl != INVALID_HANDLE_VALUE) ::CloseHandle(hndl); } };
    using _handle_t = std::unique_ptr<void, decltype(HandleDeleter)>;

    constexpr inline auto GlobMemDeleter{ [](BYTE *const ptr) noexcept { if (ptr) ::GlobalFree(ptr); } };
    using _loclmem_t = std::unique_ptr<BYTE, decltype(GlobMemDeleter)>;
  }

  // only use for HANDLE values that need to be released using CloseHandle()
  // don't rely on operator bool(), use the IsInvalidHandle lambda instead
  constexpr inline auto MakeHandle{ [](const HANDLE hndl = nullptr) noexcept { return detail::_handle_t{ hndl, detail::HandleDeleter }; } };
  constexpr inline auto IsInvalidHandle{ [](const detail::_handle_t &safeHndl) noexcept { return !safeHndl || safeHndl.get() == INVALID_HANDLE_VALUE; } };

  // only use for pointers that GlobalAlloc() returned
  constexpr inline auto MakeGlobMem{ [](BYTE *const ptr = nullptr) noexcept { return detail::_loclmem_t{ ptr, detail::GlobMemDeleter }; } };
}

namespace termproc::termname
{
  static std::wstring GetProcBaseName(const HANDLE hProc)
  {
    if (!hProc)
      return {};

    std::array<wchar_t, 1024> nameBuf{};
    auto size{ static_cast<DWORD>(nameBuf.size()) };
    if (!::QueryFullProcessImageNameW(hProc, 0, nameBuf.data(), &size))
      return {};

    return std::filesystem::path{ { nameBuf.data(), size } }.stem().wstring();
  }

  std::wstring GetTermBaseName(const DWORD termPid)
  {
    const auto sHTerm{ saferes::MakeHandle(termPid ? ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, termPid) : nullptr) };
    return GetProcBaseName(sHTerm.get());
  }
}

namespace termproc::termpid
{
  namespace detail
  {
    // undocumented SYSTEM_HANDLE structure, SYSTEM_HANDLE_TABLE_ENTRY_INFO might be the actual name
    struct SYSTEM_HANDLE
    {
      const DWORD ProcId; // PID of the process the SYSTEM_HANDLE belongs to
      const BYTE ObjTypeId; // identifier of the object
      const BYTE Flgs;
      const WORD Handle; // value representing an opened handle in the process
      const PVOID pObj;
      const DWORD Acc;
    };

    // Enumerate the opened handles in each process, select those that refer to the same process as findOpenProcId.
    // Return the ID of the process that opened the handle if its name is the same as searchProcName,
    // Return 0 if no such process is found.
    static DWORD GetPidOfNamedProcWithOpenProcHandle(std::wstring_view searchProcName, const DWORD findOpenProcId)
    {
      using NtQuerySystemInformation_t = NTSTATUS(__stdcall *)(int SysInfClass, PVOID SysInf, DWORD SysInfLen, PDWORD RetLen);
      using CompareObjectHandles_t = BOOL(__stdcall *)(HANDLE hFirst, HANDLE hSecond);

      static constexpr auto STATUS_INFO_LENGTH_MISMATCH{ static_cast<NTSTATUS>(0xc0000004) }; // NTSTATUS returned if we still didn't allocate enough memory
      static constexpr auto SystemHandleInformation{ 16 }; // one of the SYSTEM_INFORMATION_CLASS values
      static constexpr BYTE OB_TYPE_INDEX_JOB{ 7 }; // one of the SYSTEM_HANDLE.ObjTypeId values

      NtQuerySystemInformation_t NtQuerySystemInformation{};
      CompareObjectHandles_t CompareObjectHandles{};

      HMODULE hModule{ ::GetModuleHandleA("ntdll.dll") };
      if (!hModule || !(NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(::GetProcAddress(hModule, "NtQuerySystemInformation"))))
        return {};

      hModule = ::GetModuleHandleA("kernelbase.dll");
      if (!hModule || !(CompareObjectHandles = reinterpret_cast<CompareObjectHandles_t>(::GetProcAddress(hModule, "CompareObjectHandles"))))
        return {};

      // allocate some memory representing an undocumented SYSTEM_HANDLE_INFORMATION object, which can't be meaningfully declared in C# code
      DWORD infSize{ 0x200000 };
      auto sPSysHandlInf{ saferes::MakeGlobMem(static_cast<BYTE *>(::GlobalAlloc(GMEM_FIXED, infSize))) };
      if (!sPSysHandlInf)
        return {};

      DWORD len;
      NTSTATUS status;
      // try to get an array of all available SYSTEM_HANDLE objects, allocate more memory if necessary
      while ((status = NtQuerySystemInformation(SystemHandleInformation, sPSysHandlInf.get(), infSize, &len)) == STATUS_INFO_LENGTH_MISMATCH)
      {
        infSize = len + 0x1000;
        sPSysHandlInf.reset(static_cast<BYTE *>(::GlobalAlloc(GMEM_FIXED, infSize)));
        if (!sPSysHandlInf)
          return {};
      }

      if (!NT_SUCCESS(status))
        return {};

      const auto sHFindOpenProc{ saferes::MakeHandle(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, findOpenProcId)) }; // intentionally after NtQuerySystemInformation() was called to exclude it from the found open handles
      if (saferes::IsInvalidHandle(sHFindOpenProc))
        return {};

      const HANDLE hThis{ GetCurrentProcess() };
      DWORD curPid{};
      auto sHCur{ saferes::MakeHandle() };
      // iterate over the array of SYSTEM_HANDLE objects, which begins at an offset of pointer size in the SYSTEM_HANDLE_INFORMATION object
      // the number of SYSTEM_HANDLE objects is specified in the first 32 bits of the SYSTEM_HANDLE_INFORMATION object
      for (const auto &sysHandle :
           std::span{ reinterpret_cast<detail::SYSTEM_HANDLE *>(sPSysHandlInf.get() + sizeof(intptr_t)), *reinterpret_cast<DWORD *>(sPSysHandlInf.get()) })
      {
        // shortcut; OB_TYPE_INDEX_JOB is the identifier we are looking for, any other SYSTEM_HANDLE object is immediately ignored at this point
        if (sysHandle.ObjTypeId != OB_TYPE_INDEX_JOB)
          continue;

        // every time the process changes, the previous handle needs to be closed and we open a new handle to the current process
        if (curPid != sysHandle.ProcId)
        {
          curPid = sysHandle.ProcId;
          sHCur.reset(::OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, curPid));
        }

        HANDLE hCurOpenDup{};
        // if the process has not been opened, or
        // if duplicating the current one of its open handles fails, continue with the next SYSTEM_HANDLE object
        // the duplicated handle is necessary to get information about the object (e.g. the process) it points to
        if (saferes::IsInvalidHandle(sHCur) ||
            !::DuplicateHandle(sHCur.get(), reinterpret_cast<HANDLE>(sysHandle.Handle), hThis, &hCurOpenDup, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0))
          continue;

        const auto sHCurOpenDup{ saferes::MakeHandle(hCurOpenDup) };
        if (CompareObjectHandles(sHCurOpenDup.get(), sHFindOpenProc.get()) && // both the handle of the open process and the currently duplicated handle must refer to the same kernel object
            searchProcName == termproc::termname::GetProcBaseName(sHCur.get())) // the process name of the currently found process must meet the process name we are looking for
          return curPid;
      }

      return {};
    }
  }

  DWORD GetTermPid()
  {
    static bool isDetermined{};
    static DWORD termPid{};
    // Skip the long-winded code, the PID needs to be determined only once.
    if (isDetermined)
      return termPid;

    isDetermined = true;
    const auto conWnd{ ::GetConsoleWindow() };
    DWORD shellPid{};
    // Get the ID of the Shell process that spawned the Conhost process.
    ::GetWindowThreadProcessId(conWnd, &shellPid);
    // We don't have a proper way to figure out to what terminal app the Shell process
    // is connected on the local machine:
    // https://github.com/microsoft/terminal/issues/7434
    // We're getting around this assuming we don't get an icon handle from the
    // invisible Conhost window when the Shell is connected to Windows Terminal.
    if (::SendMessageW(conWnd, WM_GETICON, 0, 0))
    {
      // Conhost assumed: The Shell process' main window is the console window.
      // (weird because the Shell has no own window, but it has always been like this)
      return (termPid = shellPid);
    }

    return (termPid = detail::GetPidOfNamedProcWithOpenProcHandle(L"WindowsTerminal", shellPid));
  }
}

namespace termproc::termwnd
{
  namespace detail
  {
    using _wnd_callback_dat_t = std::pair<const DWORD, HWND>;
    static BOOL __stdcall GetTermWndCallback(HWND hWnd, LPARAM lParam) noexcept
    {
      const auto pSearchDat{ reinterpret_cast<_wnd_callback_dat_t *>(lParam) };
      DWORD pid{};
      ::GetWindowThreadProcessId(hWnd, &pid);
      if (pid != pSearchDat->first || !::IsWindowVisible(hWnd) || ::GetWindow(hWnd, GW_OWNER))
        return TRUE;

      pSearchDat->second = hWnd;
      return FALSE;
    }
  }

  HWND GetTermWnd(const DWORD termPid) noexcept
  {
    if (!termPid)
      return nullptr;

    detail::_wnd_callback_dat_t searchDat{ termPid, nullptr };
    ::EnumWindows(detail::GetTermWndCallback, reinterpret_cast<LPARAM>(&searchDat));
    return searchDat.second;
  }
}

#include <ranges>

void test::Fade(const HWND hWnd, const FadeMode mode) noexcept
{
  ::SetWindowLongW(hWnd, GWL_EXSTYLE, ::GetWindowLongW(hWnd, GWL_EXSTYLE) | WS_EX_LAYERED);

  constexpr std::ranges::iota_view rng{ 0, 86 };
  if (mode == FadeMode::Out)
  {
    for (const auto alpha : std::ranges::reverse_view{ rng })
    {
      ::SetLayeredWindowAttributes(hWnd, 0, static_cast<BYTE>(alpha * 3), LWA_ALPHA);
      ::Sleep(1);
    }

    return;
  }

  for (const auto alpha : rng)
  {
    ::SetLayeredWindowAttributes(hWnd, 0, static_cast<BYTE>(alpha * 3), LWA_ALPHA);
    ::Sleep(1);
  }
}

#ifdef NDEBUG
#  if defined(__GNUC__) || defined(__clang__)
#    pragma GCC diagnostic pop
#  elif defined(_MSC_VER)
#    pragma warning(pop)
#  endif
#endif
