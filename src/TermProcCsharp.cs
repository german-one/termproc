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

// Min. req.: .NET Framework 4.5

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace TerminalProcess
{
  // provides the TermProc property referencing the process of the terminal connected to the current console application
  public static class WinTerm
  {
    // imports the used Windows API functions
    private static class NativeMethods
    {
      [DllImport("kernel32.dll")]
      internal static extern int CloseHandle(IntPtr Hndl);
      [DllImport("kernelbase.dll")]
      internal static extern int CompareObjectHandles(IntPtr hFirst, IntPtr hSecond);
      [DllImport("kernel32.dll")]
      internal static extern int DuplicateHandle(IntPtr SrcProcHndl, IntPtr SrcHndl, IntPtr TrgtProcHndl, out IntPtr TrgtHndl, int Acc, int Inherit, int Opts);
      [DllImport("kernel32.dll")]
      internal static extern IntPtr GetConsoleWindow();
      [DllImport("kernel32.dll")]
      internal static extern IntPtr GetCurrentProcess();
      [DllImport("user32.dll")]
      internal static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint procId);
      [DllImport("ntdll.dll")]
      internal static extern int NtQuerySystemInformation(int SysInfClass, IntPtr SysInf, int SysInfLen, out int RetLen);
      [DllImport("kernel32.dll")]
      internal static extern IntPtr OpenProcess(int Acc, int Inherit, uint ProcId);
      [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
      internal static extern int QueryFullProcessImageNameW(IntPtr Proc, int Flgs, StringBuilder Name, ref int Size);
      [DllImport("user32.dll")]
      internal static extern IntPtr SendMessageW(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);
    }

    // owns an unmanaged resource
    // the ctor qualifies a SafeRes object to manage either a pointer received from Marshal.AllocHGlobal(), or a handle
    private class SafeRes : CriticalFinalizerObject, IDisposable
    {
      // resource type of a SafeRes object
      internal enum ResType
      {
        MemoryPointer,
        Handle
      }

      private readonly ResType resourceType = ResType.MemoryPointer;

      internal IntPtr Raw { get; private set; } = IntPtr.Zero;

      internal bool IsInvalid
      {
        get { return Raw == IntPtr.Zero || Raw == new IntPtr(-1); }
      }

      // constructs a SafeRes object from an unmanaged resource specified by parameter raw
      // the resource must be either a pointer received from Marshal.AllocHGlobal() (specify resourceType ResType.MemoryPointer),
      // or a handle (specify resourceType ResType.Handle)
      internal SafeRes(IntPtr raw, ResType resourceType)
      {
        Raw = raw;
        this.resourceType = resourceType;
      }

      ~SafeRes()
      {
        Dispose(false);
      }

      public void Dispose()
      {
        Dispose(true);
        GC.SuppressFinalize(this);
      }

      protected virtual void Dispose(bool disposing)
      {
        if (IsInvalid)
        {
          return;
        }

        if (resourceType == ResType.MemoryPointer)
        {
          Marshal.FreeHGlobal(Raw);
          Raw = IntPtr.Zero;
          return;
        }

        if (NativeMethods.CloseHandle(Raw) != 0)
        {
          Raw = new IntPtr(-1);
        }
      }

      internal virtual void Reset(IntPtr raw)
      {
        Dispose();
        Raw = raw;
      }
    }

    // undocumented SYSTEM_HANDLE structure, SYSTEM_HANDLE_TABLE_ENTRY_INFO might be the actual name
    [StructLayout(LayoutKind.Sequential)]
    private readonly struct SystemHandle
    {
      internal readonly uint ProcId; // PID of the process the SYSTEM_HANDLE belongs to
      internal readonly byte ObjTypeId; // identifier of the object
      internal readonly byte Flgs;
      internal readonly ushort Handle; // value representing an opened handle in the process
      internal readonly IntPtr pObj;
      internal readonly uint Acc;
    }

    private static string GetProcBaseName(SafeRes sHProc)
    {
      int size = 1024;
      StringBuilder nameBuf = new StringBuilder(size);
      return NativeMethods.QueryFullProcessImageNameW(sHProc.Raw, 0, nameBuf, ref size) == 0
        ? ""
        : Path.GetFileNameWithoutExtension(nameBuf.ToString(0, size));
    }

    // Enumerate the opened handles in each process, select those that refer to the same process as findOpenProcId.
    // Return the ID of the process that opened the handle if its name is the same as searchProcName,
    // Return 0 if no such process is found.
    private static uint GetPidOfNamedProcWithOpenProcHandle(string searchProcName, uint findOpenProcId)
    {
      const int PROCESS_DUP_HANDLE = 0x0040, // access right to duplicate handles
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, // access right to retrieve certain process information
                STATUS_INFO_LENGTH_MISMATCH = -1073741820, // NTSTATUS returned if we still didn't allocate enough memory
                SystemHandleInformation = 16; // one of the SYSTEM_INFORMATION_CLASS values
      const byte OB_TYPE_INDEX_JOB = 7; // one of the SYSTEM_HANDLE.ObjTypeId values
      int status, // retrieves the NTSTATUS return value
          infSize = 0x200000; // initially allocated memory size for the SYSTEM_HANDLE_INFORMATION object

      // allocate some memory representing an undocumented SYSTEM_HANDLE_INFORMATION object, which can't be meaningfully declared in C# code
      using (SafeRes sPSysHndlInf = new SafeRes(Marshal.AllocHGlobal(infSize), SafeRes.ResType.MemoryPointer))
      {
        // try to get an array of all available SYSTEM_HANDLE objects, allocate more memory if necessary
        while ((status = NativeMethods.NtQuerySystemInformation(SystemHandleInformation, sPSysHndlInf.Raw, infSize, out int len)) == STATUS_INFO_LENGTH_MISMATCH)
        {
          sPSysHndlInf.Reset(Marshal.AllocHGlobal(infSize = len + 0x1000));
        }

        if (status < 0)
        {
          return 0;
        }

        using (SafeRes sHFindOpenProc = new SafeRes(NativeMethods.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, findOpenProcId), SafeRes.ResType.Handle)) // intentionally after NtQuerySystemInformation() was called to exclude it from the found open handles
        {
          if (sHFindOpenProc.IsInvalid)
          {
            return 0;
          }

          uint foundPid = 0;
          uint curPid = 0;
          IntPtr hThis = NativeMethods.GetCurrentProcess();
          int sysHndlSize = Marshal.SizeOf(typeof(SystemHandle));
          using (SafeRes sHCur = new SafeRes(IntPtr.Zero, SafeRes.ResType.Handle))
          {
            // iterate over the array of SYSTEM_HANDLE objects, which begins at an offset of pointer size in the SYSTEM_HANDLE_INFORMATION object
            // the number of SYSTEM_HANDLE objects is specified in the first 32 bits of the SYSTEM_HANDLE_INFORMATION object
            for (IntPtr pSysHndl = sPSysHndlInf.Raw + IntPtr.Size, pEnd = pSysHndl + (Marshal.ReadInt32(sPSysHndlInf.Raw) * sysHndlSize); pSysHndl != pEnd; pSysHndl += sysHndlSize)
            {
              // get one SYSTEM_HANDLE at a time
              SystemHandle sysHndl = (SystemHandle)Marshal.PtrToStructure(pSysHndl, typeof(SystemHandle));
              // shortcut; OB_TYPE_INDEX_JOB is the identifier we are looking for, any other SYSTEM_HANDLE object is immediately ignored at this point
              if (sysHndl.ObjTypeId != OB_TYPE_INDEX_JOB)
              {
                continue;
              }

              // every time the process changes, the previous handle needs to be closed and we open a new handle to the current process
              if (curPid != sysHndl.ProcId)
              {
                curPid = sysHndl.ProcId;
                sHCur.Reset(NativeMethods.OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, 0, curPid));
              }

              // if the process has not been opened, or
              // if duplicating the current one of its open handles fails, continue with the next SYSTEM_HANDLE object
              // the duplicated handle is necessary to get information about the object (e.g. the process) it points to
              if (sHCur.IsInvalid ||
                  NativeMethods.DuplicateHandle(sHCur.Raw, (IntPtr)sysHndl.Handle, hThis, out IntPtr hCurOpenDup, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0) == 0)
              {
                continue;
              }

              using (SafeRes sHCurOpenDup = new SafeRes(hCurOpenDup, SafeRes.ResType.Handle))
              {
                if (NativeMethods.CompareObjectHandles(sHCurOpenDup.Raw, sHFindOpenProc.Raw) != 0 && // both the handle of the open process and the currently duplicated handle must refer to the same kernel object
                    searchProcName == GetProcBaseName(sHCur)) // the process name of the currently found process must meet the process name we are looking for
                {
                  foundPid = curPid;
                  break;
                }
              }
            }
          }

          return foundPid;
        }
      }
    }

    private static IntPtr ConWnd { get; } = NativeMethods.GetConsoleWindow();

    private static Process GetTermProc()
    {
      const int WM_GETICON = 0x007F;

      // Get the ID of the Shell process that spawned the Conhost process.
      if (NativeMethods.GetWindowThreadProcessId(ConWnd, out uint shellPid) == 0)
      {
        return null;
      }

      // We don't have a proper way to figure out to what terminal app the Shell process
      // is connected on the local machine:
      // https://github.com/microsoft/terminal/issues/7434
      // We're getting around this assuming we don't get an icon handle from the
      // invisible Conhost window when the Shell is connected to Windows Terminal.
      if (NativeMethods.SendMessageW(ConWnd, WM_GETICON, IntPtr.Zero, IntPtr.Zero) != IntPtr.Zero)
      {
        // Conhost assumed: The Shell process' main window is the console window.
        // (weird because the Shell has no own window, but it has always been like this)
        return Process.GetProcessById((int)shellPid);
      }

      // We don't have a proper way to figure out which WindowsTerminal process
      // is connected with the Shell process:
      // https://github.com/microsoft/terminal/issues/5694
      // The assumption that the terminal is the parent process of the Shell process
      // is gone with DefTerm (the Default Windows Terminal).
      // Thus, I don't care about using more undocumented stuff:
      // Try to figure out which of WindowsTerminal processes has a handle to the Shell process open.
      uint termPid = GetPidOfNamedProcWithOpenProcHandle("WindowsTerminal", shellPid);
      return termPid == 0 ? null : Process.GetProcessById((int)termPid);
    }

    // Get the process of the terminal connected to the current console application.
    // Only Windows Terminal and Conhost are supported.
    // Value:
    //  If the terminal is Windows Terminal, the process of the belonging Windows Terminal instance will be returned.
    //  If the terminal is Conhost, the process of the console application that spawned the Conhost instance will be returned.
    //  If the function fails, null will be returned.
    public static Process TermProc { get; } = GetTermProc();
  }

  internal class Program
  {
#if !DEBUG && CODE_ANALYSIS
#pragma warning disable IDE0079
    [SuppressMessage("Microsoft.Globalization", "CA1303:DoNotPassLiteralsAsLocalizedParameters")] // WriteLine()
#pragma warning restore IDE0079
#endif
    private static int Main()
    {
      try
      {
        Console.WriteLine("Term proc: {0}\nTerm PID:  {1}\nTerm HWND: {2}",
          WinTerm.TermProc.ProcessName,
          WinTerm.TermProc.Id.ToString(CultureInfo.CurrentCulture),
          WinTerm.TermProc.MainWindowHandle.ToString("X8"));

        Test.Fader.Fade(WinTerm.TermProc.MainWindowHandle, Test.FadeMode.Out);
        Test.Fader.Fade(WinTerm.TermProc.MainWindowHandle, Test.FadeMode.In);
        return 0;
      }
      catch
      {
        return 1;
      }
    }
  }
}

namespace Test
{
  //# for the second parameter of the Fader.Fade() method
  public enum FadeMode { Out, In }

  //# provides the .Fade() method for fading out or fading in a window, used to prove that we found the right terminal process
  public static class Fader
  {
    private static class NativeMethods
    {
      [DllImport("user32.dll")]
      internal static extern int GetWindowLongW(IntPtr wnd, int idx);
      [DllImport("user32.dll")]
      internal static extern int SetLayeredWindowAttributes(IntPtr wnd, int color, int alpha, int flags);
      [DllImport("user32.dll")]
      internal static extern int SetWindowLongW(IntPtr wnd, int idx, int newLong);
    }

    //# use alpha blending to fade the window
    public static void Fade(IntPtr hWnd, FadeMode mode)
    {
      if (hWnd == IntPtr.Zero) { return; }

      const int GWL_EXSTYLE = -20,
                WS_EX_LAYERED = 0x80000,
                LWA_ALPHA = 2;

      if (NativeMethods.SetWindowLongW(hWnd, GWL_EXSTYLE, NativeMethods.GetWindowLongW(hWnd, GWL_EXSTYLE) | WS_EX_LAYERED) == 0) { return; }

      if (mode == FadeMode.Out)
      {
        for (int alpha = 255; alpha >= 0; alpha -= 3)
        {
          if (NativeMethods.SetLayeredWindowAttributes(hWnd, 0, alpha, LWA_ALPHA) == 0) { return; }
          Thread.Sleep(1);
        }
        return;
      }

      for (int alpha = 0; alpha <= 255; alpha += 3)
      {
        if (NativeMethods.SetLayeredWindowAttributes(hWnd, 0, alpha, LWA_ALPHA) == 0) { return; }
        Thread.Sleep(1);
      }
    }
  }
}
