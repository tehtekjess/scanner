using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace virus_scanner
{
    class MemoryReader
    {
        const int PROCESS_WM_READ = 0x0010;

        public enum AllocationProtectEnum : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        public enum StateEnum : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        public enum TypeEnum : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public AllocationProtectEnum AllocationProtect;
            public IntPtr RegionSize;
            public StateEnum State;
            public AllocationProtectEnum Protect;
            public TypeEnum Type;
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, ref IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern uint VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        IntPtr ProcessHandle;
        Process Process;

        public void scan()
        {
            IntPtr addr = IntPtr.Zero;
            do
            {
                MEMORY_BASIC_INFORMATION info = new MEMORY_BASIC_INFORMATION();
                uint query_return = VirtualQueryEx(this.ProcessHandle, addr, out info, Marshal.SizeOf(info));
                if (query_return == 0)
                {
                    addr += 4096;
                    continue;
                }

                int regionSize = info.RegionSize.ToInt32();
                if (info.State == StateEnum.MEM_COMMIT && (info.Protect & AllocationProtectEnum.PAGE_GUARD) != AllocationProtectEnum.PAGE_GUARD)
                {
                    // Good memory to scan -- Lets read the region
                    byte[] Buffer = this.ReadBytes(addr, regionSize);
                    // Todo: Add code to merge regions into a single buffer and then scan the buffer for a signature.
                }

                // Not sure if I want to iterate by region size or just go in chunks of the system page size
                addr = IntPtr.Add(info.BaseAddress, regionSize);

            } while (addr != IntPtr.Zero && addr.ToInt64() < 0x7FFFFFFFFFFF0000);
        }

        public void Open(Process P)
        {
            this.Process = P;
            this.ProcessHandle = OpenProcess(PROCESS_WM_READ, false, P.Id);
        }

        public bool IsProcessOpen
        {
            get
            {
                if (Process == null)
                    return false;

                return !Process.HasExited && ProcessHandle != IntPtr.Zero;
            }
        }

        public byte[] ReadBytes(IntPtr Address, int Size)
        {
            IntPtr Read = IntPtr.Zero;
            byte[] Buffer = new byte[Size];

            if (ReadProcessMemory(ProcessHandle, Address, Buffer, Size, ref Read))
                return Buffer;

            return default(byte[]);
        }

        public byte ReadByte(IntPtr Address)
        {
            var B = ReadBytes(Address, 1);

            if (B != null)
                return B[0];

            return default(byte);
        }

        public uint ReadUInt(IntPtr Address)
        {
            var B = ReadBytes(Address, 4);

            if (B != null)
                return BitConverter.ToUInt32(B, 0);

            return default(uint);
        }

        public ulong ReadUInt64(IntPtr Address)
        {
            var B = ReadBytes(Address, 8);

            if (B != null)
                return BitConverter.ToUInt64(B, 0);

            return default(ulong);
        }
    }
}
