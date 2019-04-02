using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace AppStartService
{
    public class StartApplication
    {

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSSendMessage(
            IntPtr hServer,
            int SessionId,
            String pTitle,
            int TitleLength,
            String pMessage,
            int MessageLength,
            int Style,
            int Timeout,
            out int pResponse,
            bool bWait);
        /// <summary>
        /// 
        /// 
        /// https://www.cnblogs.com/findumars/p/6147915.html
        /// https://blog.csdn.net/kevindr/article/details/77008537
        /// https://blog.csdn.net/liujiayu2/article/details/77233492?tdsourcetag=s_pcqq_aiomsg
        /// https://docs.microsoft.com/zh-cn/windows/desktop/SecAuthZ/access-rights-for-access-token-objects
        /// https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        /// https://docs.microsoft.com/zh-cn/windows/desktop/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
        /// https://www.baidu.com/link?url=vfRlOgZepG6LgDHn5Iy4DW_BhqjhBv4F8LbgOh-ZuKdJFTFW5py25ye-K0XLDFErQGz-vtzmYITrbEtsLXH0Ya&wd=&eqid=aeae9b9000088884000000065c9625af
        /// </summary>
        /// <param name="app"></param>
        /// <param name="path"></param>
        public static void CreateProcess(string app, string path)
        {
            EventLog log = new EventLog();

            bool result;
            IntPtr hUserToken = WindowsIdentity.GetCurrent().Token;

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.Length = Marshal.SizeOf(sa);

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            //si.lpDesktop = "winsta0\\default";

            int dwSessionID = WTSGetActiveConsoleSessionId();
            result = WTSQueryUserToken(dwSessionID, out hUserToken);
            log.WriteEntry($"SessionId:{dwSessionID}\r\nUserToken:{hUserToken}", EventLogEntryType.Information);

            if (!result)
            {
                log.WriteEntry($"WTSQueryUserToken failed,error:" + Marshal.GetLastWin32Error(), EventLogEntryType.Warning);
            }

            IntPtr hPToken = IntPtr.Zero;
            result = OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES |
                TOKEN_QUERY |
                TOKEN_DUPLICATE |
                TOKEN_ASSIGN_PRIMARY |
                TOKEN_ADJUST_SESSIONID |
                TOKEN_READ |
                TOKEN_WRITE, out hPToken);
            if (!result)
            {
                log.WriteEntry($"OpenProcessToken failed,error:" + Marshal.GetLastWin32Error(), EventLogEntryType.Warning);
            }

            LUID luid = new LUID();
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
            {
                log.WriteEntry($"LookupPrivilegeValue failed,error:" + Marshal.GetLastWin32Error(), EventLogEntryType.Warning);
            }
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.Privileges = new LUID_AND_ATTRIBUTES[1];
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            IntPtr hUserTokenDup = IntPtr.Zero;
            result = DuplicateTokenEx(
                  hPToken,
                  MAXIMUM_ALLOWED,
                  ref sa,
                  (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                  (int)TOKEN_TYPE.TokenPrimary,
                  ref hUserTokenDup
               );

            if (!result)
            {
                log.WriteEntry($"DuplicateTokenEx failed,error:" + Marshal.GetLastWin32Error(), EventLogEntryType.Warning);
            }

            if (!SetTokenInformation(hUserTokenDup, (int)TOKEN_INFORMATION_CLASS.TokenSessionId, ref dwSessionID, Marshal.SizeOf(typeof(int))))
            {
                log.WriteEntry($"SetTokenInformation failed,error:" + Marshal.GetLastWin32Error(), EventLogEntryType.Warning);
            }

            try
            {
                if (!AdjustTokenPrivileges(hUserTokenDup, false, tp, Marshal.SizeOf<TOKEN_PRIVILEGES>(), /*ref preToken, ref preTokenLen*/IntPtr.Zero, IntPtr.Zero))
                {
                    log.WriteEntry($"AdjustTokenPrivileges failed,error:" + Marshal.GetLastWin32Error(), EventLogEntryType.Warning);
                }

            }
            catch (Exception ex)
            {
                log.WriteEntry($"AdjustTokenPrivileges failed,error:\r\n errorCode:{Marshal.GetLastWin32Error()}\r\n {ex.Message}", EventLogEntryType.Warning);
            }
            IntPtr lpEnvironment = IntPtr.Zero;
            int dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;

            result = CreateEnvironmentBlock(out lpEnvironment, hUserTokenDup, true);

            if (result)
            {
                dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
            }
            else
            {
                log.WriteEntry("CreateEnvironmentBlock failed,error:" + Marshal.GetLastWin32Error(), EventLogEntryType.Warning);
            }

            result = CreateProcessAsUser(
                                 hUserTokenDup,
                                 app,
                                 String.Empty,
                                 ref sa,
                                 ref sa,
                                 false,
                                 dwCreationFlags,
                                 lpEnvironment,
                                 path,
                                 ref si,
                                 ref pi);

            if (!result)
            {
                int errCode = Marshal.GetLastWin32Error();
                log.WriteEntry("CreateEnvironmentBlock failed,error:" + errCode, EventLogEntryType.Warning);
            }

            if (pi.hProcess != IntPtr.Zero)
                CloseHandle(pi.hProcess);
            if (pi.hThread != IntPtr.Zero)
                CloseHandle(pi.hThread);
            if (hUserTokenDup != IntPtr.Zero)
                CloseHandle(hUserTokenDup);
        }

        public static void ShowMessageBox(string message, string title)
        {
            int resp = 0;
            WTSSendMessage(
                WTS_CURRENT_SERVER_HANDLE,
                WTSGetActiveConsoleSessionId(),
                title, title.Length,
                message, message.Length,
                0, 0, out resp, false);
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 dwProcessID;
            public Int32 dwThreadID;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public Int32 Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {

            public uint LowPart;
            public long HighPart;
            public IntPtr PLuid;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public long Attributes;
        }


        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            TokenProcessTrustLevel,
            TokenPrivateNameSpace,
            TokenSingletonAttributes,
            TokenBnoIsolation,
            TokenChildProcessFlags,
            MaxTokenInfoClass,
            TokenIsLessPrivilegedAppContainer
        }

        public static IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        public const int GENERIC_ALL_ACCESS = 0x10000000;


        public const Int64 SE_PRIVILEGE_ENABLED = 0x00000002L;
        public const int TOKEN_QUERY = 0x0008;
        public const int TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const int TOKEN_DUPLICATE = 0x0002;
        public const int TOKEN_IMPERSONATE = 0x0004;
        public const int TOKEN_ADJUST_DEFAULT = 0x0080;
        public const int TOKEN_ADJUST_SESSIONID = 0x0100;
        public const int TOKEN_READ = 131080;
        public const int TOKEN_WRITE = 131296;
        public const int TOKEN_QUERY_SOURCE = 0x0010;
        public const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const int TOKEN_ADJUST_GROUPS = 0x0040;

        public const int MAXIMUM_ALLOWED = 0x02000000;
        public const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        public const int NORMAL_PRIORITY_CLASS = 0x20;
        public const int CREATE_NEW_CONSOLE = 0x00000010;

        [DllImport("kernel32.dll", SetLastError = true,
            CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CloseHandle(IntPtr handle);


        [DllImport("kernel32.dll", SetLastError = true,
            CharSet = CharSet.Auto)]
        public static extern IntPtr GetCurrentProcess();


        [DllImport("advapi32.dll", SetLastError = true,
            CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandle,
            Int32 dwCreationFlags,
            IntPtr lpEnvrionment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            ref PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
             IntPtr processHandle,
             Int32 desiredAccess,
             out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(
            IntPtr hExistingToken,
            Int32 dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            Int32 ImpersonationLevel,
            Int32 dwTokenType,
            ref IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSQueryUserToken(
            Int32 sessionId,
            out IntPtr Token);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetTokenInformation(
           IntPtr TokenHandle,
          int TokenInformationClass,
          ref int TokenInformation,
          int TokenInformationLength
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            TOKEN_PRIVILEGES NewState,
            int BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength
        );

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(
            out IntPtr lpEnvironment,
            IntPtr hToken,
            bool bInherit);

    }
}
