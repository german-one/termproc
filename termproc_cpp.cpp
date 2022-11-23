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
#define _WIN32_WINNT 0x0601
#if defined(NDEBUG) && defined(__clang__)
#  pragma GCC diagnostic pop
#endif
#undef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>
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
    const auto termPid = termproc::termpid::GetTermPid();
    if (!termPid)
      return 1;

    const auto termWnd = termproc::termwnd::GetTermWnd(termPid);
    std::wcout << L"Term proc: " << termproc::termname::GetTermBaseName(termPid)
               << L"\nTerm PID:  " << termPid
               << L"\nTerm HWND: " << std::setfill(L'0') << std::setw(8) << std::right << std::uppercase << std::hex << reinterpret_cast<UINT_PTR>(termWnd) << std::endl;

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

#include <Psapi.h>
#include <SubAuth.h>
#include <TlHelp32.h>
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

    constexpr inline auto LoclMemDeleter{ [](BYTE *const ptr) noexcept { if (ptr) ::LocalFree(ptr); } };
    using _loclmem_t = std::unique_ptr<BYTE, decltype(LoclMemDeleter)>;
  }

  // only use for HANDLE values that need to be released using CloseHandle()
  // don't rely on operator bool(), use the IsInvalidHandle lambda instead
  constexpr inline auto MakeHandle{ [](const HANDLE hndl = nullptr) noexcept { return detail::_handle_t{ hndl, detail::HandleDeleter }; } };
  constexpr inline auto IsInvalidHandle{ [](const detail::_handle_t &safeHndl) noexcept { return !safeHndl || safeHndl.get() == INVALID_HANDLE_VALUE; } };

  // only use for pointers that LocalAlloc() returned
  constexpr inline auto MakeLoclMem{ [](BYTE *const ptr = nullptr) noexcept { return detail::_loclmem_t{ ptr, detail::LoclMemDeleter }; } };
}

namespace termproc::termpid
{
  namespace detail
  {
    // undocumented SYSTEM_HANDLE structure, SYSTEM_HANDLE_TABLE_ENTRY_INFO might be the actual name
    struct SYSTEM_HANDLE
    {
      const DWORD ProcId; // PID of the process the SYSTEM_HANDLE belongs to
      const BYTE ObjTypeNum;
      const BYTE Flags;
      const WORD Handle; // value representing an opened handle in the process
      const PVOID pObj;
      const DWORD Acc;
    };

    class FnDynLoad
    {
      const HMODULE _hModule{};

      template<typename fnptrT>
      constexpr auto GetFunc(const char *const name) noexcept
      {
        return _hModule ? reinterpret_cast<fnptrT>(::GetProcAddress(_hModule, name)) : fnptrT{};
      }

    public:
      using NtQuerySystemInformation_t = NTSTATUS(__stdcall *)(int SysInfClass, PVOID SysInf, DWORD SysInfLen, PDWORD RetLen);
      using NtQueryObject_t = NTSTATUS(__stdcall *)(HANDLE ObjHandle, int ObjInfClass, PVOID ObjInf, DWORD ObjInfLen, PDWORD RetLen);

      const NtQuerySystemInformation_t NtQuerySystemInformation{};
      const NtQueryObject_t NtQueryObject{};

      FnDynLoad() noexcept :
        _hModule{ ::GetModuleHandleA("ntdll.dll") },
        NtQuerySystemInformation{ GetFunc<NtQuerySystemInformation_t>("NtQuerySystemInformation") },
        NtQueryObject{ GetFunc<NtQueryObject_t>("NtQueryObject") }
      {
      }

      constexpr operator bool() const noexcept
      {
        return NtQuerySystemInformation && NtQueryObject;
      }
    };

    // Enumerate the opened handles in the WindowsTerminal.exe process specified by the process ID passed to termPid.
    // Return termPid if one of the process handles points to the Shell process specified by the process ID passed to shellPid.
    // Return 0 if the Shell process is not found.
    static DWORD FindWTCallback(const DWORD shellPid, const DWORD termPid)
    {
      static constexpr std::wstring_view procHndlTypeName{ L"Process" };
      static constexpr auto STATUS_INFO_LENGTH_MISMATCH{ static_cast<NTSTATUS>(0xc0000004) }; // NTSTATUS returned if we still didn't allocate enough memory
      static constexpr auto SystemHandleInformation{ 16 }; // one of the SYSTEM_INFORMATION_CLASS values
      static constexpr auto ObjectTypeInformation{ 2 }; // one of the OBJECT_INFORMATION_CLASS values
      static constexpr DWORD typeInfoSize{ 0x1000 };

      static const FnDynLoad fns{};
      if (!fns)
        return {};

      const auto sHProc{ saferes::MakeHandle(::OpenProcess(PROCESS_DUP_HANDLE, FALSE, termPid)) };
      if (saferes::IsInvalidHandle(sHProc))
        return {};

      // allocate some memory representing an undocumented SYSTEM_HANDLE_INFORMATION object, which can't be meaningfully declared in C# code
      DWORD infSize{ 0x10000 };
      auto sPSysHandlInf{ saferes::MakeLoclMem(static_cast<BYTE *>(::LocalAlloc(LMEM_FIXED, infSize))) };
      if (!sPSysHandlInf)
        return {};

      DWORD len{};
      NTSTATUS status;
      // try to get an array of all available SYSTEM_HANDLE objects, allocate more memory if necessary
      while ((status = fns.NtQuerySystemInformation(SystemHandleInformation, sPSysHandlInf.get(), infSize, &len)) == STATUS_INFO_LENGTH_MISMATCH)
      {
        sPSysHandlInf.reset(static_cast<BYTE *>(::LocalAlloc(LMEM_FIXED, infSize = len)));
        if (!sPSysHandlInf)
          return {};
      }

      if (!NT_SUCCESS(status))
        return {};

      // allocate reusable memory for a PUBLIC_OBJECT_TYPE_INFORMATION object
      std::array<BYTE, typeInfoSize> bufTypeInfo{};
      // iterate over the array of SYSTEM_HANDLE objects, which begins at an offset of pointer size in the SYSTEM_HANDLE_INFORMATION object
      // the number of SYSTEM_HANDLE objects is specified in the first 32 bits of the SYSTEM_HANDLE_INFORMATION object
      for (const auto &sysHandle :
           std::span{ reinterpret_cast<detail::SYSTEM_HANDLE *>(sPSysHandlInf.get() + sizeof(UINT_PTR)), *reinterpret_cast<DWORD *>(sPSysHandlInf.get()) })
      {
        HANDLE hDup{};
        // if the SYSTEM_HANDLE object doesn't belong to the WindowsTerminal process, or
        // if duplicating its Handle member fails, continue with the next SYSTEM_HANDLE object
        // the duplicated handle is necessary to get information about the object (e.g. the process) it points to
        if (sysHandle.ProcId != termPid ||
            !::DuplicateHandle(sHProc.get(), reinterpret_cast<HANDLE>(sysHandle.Handle), ::GetCurrentProcess(), &hDup, PROCESS_QUERY_INFORMATION, FALSE, 0))
          continue;

        // at this point duplicating succeeded and thus, sHDup is valid
        const auto sHDup{ saferes::MakeHandle(hDup) };
        // get the belonging PUBLIC_OBJECT_TYPE_INFORMATION object
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-__public_object_type_information
        // (its first member is a UNICODE_STRING object having the same address; thus, we can entirely skip both the
        // declaration of the PUBLIC_OBJECT_TYPE_INFORMATION structure and accessing its first member to get the type name)
        // check the type name to determine whether we have a process object
        // if so, get its PID and compare it with the PID of the Shell process
        // if they are equal, we are going to step out of the loop and return the PID of the WindowsTerminal process
        if (NT_SUCCESS(fns.NtQueryObject(sHDup.get(), ObjectTypeInformation, bufTypeInfo.data(), typeInfoSize, nullptr)) &&
            procHndlTypeName.compare((reinterpret_cast<PUNICODE_STRING>(bufTypeInfo.data()))->Buffer) == 0 &&
            ::GetProcessId(sHDup.get()) == shellPid)
          return termPid;
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
    static constexpr std::wstring_view wtName{ L"WindowsTerminal.exe" };
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

    const auto sHSnap{ saferes::MakeHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) };
    if (saferes::IsInvalidHandle(sHSnap))
      return {};

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(PROCESSENTRY32W);
    if (!::Process32FirstW(sHSnap.get(), &entry))
      return {};

    // We don't have a proper way to figure out which WindowsTerminal process
    // is connected with the Shell process:
    // https://github.com/microsoft/terminal/issues/5694
    // The assumption that the terminal is the parent process of the Shell process
    // is gone with DefTerm (the Default Windows Terminal).
    // Thus, I don't care about using more undocumented stuff:
    // Get the process IDs of all WindowsTerminal processes and try to figure out
    // which of them has a handle to the Shell process open.
    do
    {
      if (wtName.compare(std::data(entry.szExeFile)) == 0)
        termPid = detail::FindWTCallback(shellPid, entry.th32ProcessID);
    } while (termPid == 0 && ::Process32NextW(sHSnap.get(), &entry));

    return termPid;
  }
}

std::wstring termproc::termname::GetTermBaseName(const DWORD termPid)
{
  if (!termPid)
    return {};

  const auto sHProc{ saferes::MakeHandle(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, termPid)) };
  if (saferes::IsInvalidHandle(sHProc))
    return {};

  std::array<wchar_t, 1024> nameBuf{};
  if (!::GetProcessImageFileNameW(sHProc.get(), nameBuf.data(), static_cast<DWORD>(nameBuf.size())))
    return {};

  return std::filesystem::path{ nameBuf.data() }.stem().wstring();
}

namespace termproc::termwnd
{
  namespace detail
  {
    using _wnd_callback_dat_t = std::pair<const DWORD, HWND>;
    static BOOL __stdcall GetTermWndCallback(HWND hWnd, LPARAM lParam) noexcept
    {
      const auto pSearchDat = reinterpret_cast<_wnd_callback_dat_t *>(lParam);
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
