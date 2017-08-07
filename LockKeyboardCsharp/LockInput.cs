using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Reflection;
using System.IO;

namespace LockKeyboardCsharp
{
    public class LockInput
    {
        public IntPtr m_lHookID = IntPtr.Zero;
        private uint[] mlShellCode = new uint[Win32.SHELL_CODE_DWORDLEN - 1];
        public void Lock(Boolean isLock)
        {

            if (isLock)
            {
                m_lHookID = Win32.SetWindowsHookEx(HookType.WH_KEYBOARD_LL, new HookProc(LowLevelKeyboardProc), Marshal.GetHINSTANCE(Assembly.GetExecutingAssembly().GetModules()[0]), 0);


            }
            else
            {
                Win32.UnhookWindowsHookEx(m_lHookID);

            }
            //Win32.BlockInput(isLock);
            lockTask(isLock);
        }
        
        
        private void lockTask(bool isLock)
        {
            try
            {
           
                IntPtr hProcess;
                int hPId;
                bool lResult;
                TOKEN_PRIVILEGES pToken;
                IntPtr hToken;
                
                hPId = GetProcessIdFromName("winlogon.exe");
                if (hPId == 0)
                {
                    return ;
                }
                lResult = Win32.OpenProcessToken(Win32.GetCurrentProcess(), Win32.TOKEN_ADJUST_PRIVILEGES | Win32.TOKEN_QUERY, out hToken);
                LUID id;
                lResult = Win32.LookupPrivilegeValue("", Win32.SE_DEBUG_NAME, out id);
                pToken.Privileges.pLuid = id;
                pToken.PrivilegeCount = 1;
                pToken.Privileges.Attributes = Win32.SE_PRIVILEGE_ENABLED;
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                uint rect = 0;
                lResult = Win32.AdjustTokenPrivileges(hToken, false, ref pToken, (uint)Marshal.SizeOf(pToken), ref tp, out rect);
                hProcess = Win32.OpenProcess(ProcessAccessFlags.All, false, hPId);
              
               if (isLock)
                {

                    if (hProcess != IntPtr.Zero)
                    {
                        Win32.NtSuspendProcess(hProcess);
                    }
                
                }
                else
                {
                    if (hProcess != IntPtr.Zero)
                    {
                        Win32.NtResumeProcess(hProcess);
                    }
                }
            }
            catch { } 
            finally
            {
                //Win32.BlockInput(false);
            }
            
        }
        private Boolean GetKeyboardState()
        {
            Boolean GetKeyboardState = Win32.GlobalFindAtom(Win32.ATOM_FLAG) != 0;
            return GetKeyboardState;
        }

        private int LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam)
        {
            KBDLLHOOKSTRUCT KBEvent = new KBDLLHOOKSTRUCT();
            if (nCode == 0)
            {
                Marshal.StructureToPtr(KBEvent, lParam, true);
                return 1;
            }
            else
            {
                return Win32.CallNextHookEx(m_lHookID, nCode, wParam.ToInt32(), lParam.ToInt32()).ToInt32();
            }
        }

        private int InsertAsmCode()
        {
            const string WinLogon = "Winlogon.exe";
            IntPtr hProcess;
            int hPId;
            bool lResult;
            TOKEN_PRIVILEGES pToken;
            IntPtr hToken;
            IntPtr hRemoteThread, hRemoteThreadID, lRemoteAddr;
            hPId = GetProcessIdFromName(WinLogon);
            if (hPId == 0)
            {
                return Marshal.GetLastWin32Error();
            }
            lResult = Win32.OpenProcessToken(Win32.GetCurrentProcess(), Win32.TOKEN_ADJUST_PRIVILEGES | Win32.TOKEN_QUERY, out hToken);
            LUID id;
            lResult = Win32.LookupPrivilegeValue("", Win32.SE_DEBUG_NAME, out id);
            pToken.Privileges.pLuid = id;
            pToken.PrivilegeCount = 1;
            pToken.Privileges.Attributes = Win32.SE_PRIVILEGE_ENABLED;
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            uint rect = 0;
            lResult = Win32.AdjustTokenPrivileges(hToken, false, ref pToken, (uint)Marshal.SizeOf(pToken), ref tp, out rect);
            hProcess = Win32.OpenProcess(ProcessAccessFlags.All, false, hPId);
            if (hProcess != IntPtr.Zero)
            {
                InitShellCode();
            }
            else
            {
                return Marshal.GetLastWin32Error();
            }
            lRemoteAddr = Win32.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)Win32.SHELL_CODE_LENGTH, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
            int ret = 0;
            if (lRemoteAddr != IntPtr.Zero)
            {
                int outret;
                bool rects = Win32.WriteProcessMemory(hProcess, lRemoteAddr, mlShellCode, (uint)Win32.SHELL_CODE_LENGTH, out outret);
            }
            else
            {
                ret = Marshal.GetLastWin32Error();
                return ret;
            }

            hRemoteThread = Win32.CreateRemoteThread(hProcess, IntPtr.Zero, 0, lRemoteAddr.ToInt32() + Win32.SHELL_FUNCOFFSET, IntPtr.Zero, 0, out hRemoteThreadID);
            if (hRemoteThread == IntPtr.Zero)
            {
                ret = Marshal.GetLastWin32Error();
                return ret;
            }

            Win32.WaitForSingleObject(hRemoteThreadID, -1);
            Win32.GetExitCodeThread(hRemoteThreadID, out ret);
            Win32.CloseHandle(hRemoteThread);
            Win32.VirtualFreeEx(hRemoteThread, lRemoteAddr, Win32.SHELL_CODE_LENGTH, FreeType.Decommit);
            return ret;
        }

        private int GetProcessIdFromName(string name)
        {
            Process[] ps = Process.GetProcesses();
            foreach (Process item in ps)
            {
                if (item.ProcessName.ToLower().Replace(".exe", "") == name.ToLower().Replace(".exe", ""))
                {
                    return item.Id;
                }
            }
            return -1;
        }
        private Process GetProcessFromName(string name)
        {
            Process[] ps = Process.GetProcesses();
            foreach (Process item in ps)
            {
                if (item.ProcessName.ToLower().Replace(".exe", "") == name.ToLower().Replace(".exe", ""))
                {
                    return item;
                }
            }
            return null;
        }

        private void InitShellCode()
        {
            const string kernel32 = "kernel32.dll";
            IntPtr hDll;

            hDll = Win32.GetModuleHandle(kernel32);
            mlShellCode[0] = Win32.GetProcAddress(hDll, "GetModuleHandleW").ToUInt32();
            mlShellCode[1] = Win32.GetProcAddress(hDll, "GetProcAddress").ToUInt32();
            mlShellCode[2] = 0xE853;
            mlShellCode[3] = 0x815B0000;
            mlShellCode[4] = 0x40100EEB;
            mlShellCode[5] = 0x238E800;
            mlShellCode[6] = 0xC00B0000;
            mlShellCode[7] = 0x838D5075;
            mlShellCode[8] = 0x4010B0;
            mlShellCode[9] = 0xD093FF50;
            mlShellCode[10] = 0xF004013;
            mlShellCode[11] = 0xC00BC0B7;
            mlShellCode[12] = 0x683A75;
            mlShellCode[13] = 0x6A020000;
            mlShellCode[14] = 0x8D006A00;
            mlShellCode[15] = 0x4010B083;
            mlShellCode[16] = 0x93FF5000;
            mlShellCode[17] = 0x401090;
            mlShellCode[18] = 0x1874C00B;
            mlShellCode[19] = 0x10C2938D;
            mlShellCode[20] = 0x6A0040;
            mlShellCode[21] = 0x93FF5052;
            mlShellCode[22] = 0x401094;
            mlShellCode[23] = 0x474C00B;
            mlShellCode[24] = 0xAEB0AEB;
            mlShellCode[25] = 0x108C93FF;
            mlShellCode[26] = 0x2EB0040;
            mlShellCode[27] = 0xC25BC033;
            mlShellCode[28] = 0xFF8B0004;
            mlShellCode[38] = 0x410053;
            mlShellCode[39] = 0x200053;
            mlShellCode[40] = 0x690077;
            mlShellCode[41] = 0x64006E;
            mlShellCode[42] = 0x77006F;
            mlShellCode[43] = 0xFF8B0000;
            mlShellCode[44] = 0x690057;
            mlShellCode[45] = 0x6C006E;
            mlShellCode[46] = 0x67006F;
            mlShellCode[47] = 0x6E006F;
            mlShellCode[48] = 0x8B550000;
            mlShellCode[49] = 0xF0C481EC;
            mlShellCode[50] = 0x53FFFFFD;
            mlShellCode[51] = 0xE8;
            mlShellCode[52] = 0xEB815B00;
            mlShellCode[53] = 0x4010D1;
            mlShellCode[54] = 0x10468;
            mlShellCode[55] = 0xF8858D00;
            mlShellCode[56] = 0x50FFFFFD;
            mlShellCode[57] = 0xFF0875FF;
            mlShellCode[58] = 0x40108093;
            mlShellCode[59] = 0xF8858D00;
            mlShellCode[60] = 0x50FFFFFD;
            mlShellCode[61] = 0x1098838D;
            mlShellCode[62] = 0xFF500040;
            mlShellCode[63] = 0x40107C93;
            mlShellCode[64] = 0x75C00B00;
            mlShellCode[65] = 0x68406A69;
            mlShellCode[66] = 0x1000;
            mlShellCode[67] = 0x7668;
            mlShellCode[68] = 0xFF006A00;
            mlShellCode[69] = 0x40107493;
            mlShellCode[70] = 0x74C00B00;
            mlShellCode[71] = 0x85896054;
            mlShellCode[72] = 0xFFFFFDF0;
            mlShellCode[73] = 0x75FFFC6A;
            mlShellCode[74] = 0x8493FF08;
            mlShellCode[75] = 0x8D004010;
            mlShellCode[76] = 0x4013C893;
            mlShellCode[77] = 0xFC028900;
            mlShellCode[78] = 0xFDF0BD8B;
            mlShellCode[79] = 0x76B9FFFF;
            mlShellCode[80] = 0x8D000000;
            mlShellCode[81] = 0x401374B3;
            mlShellCode[82] = 0x8DA4F300;
            mlShellCode[83] = 0x4010B083;
            mlShellCode[84] = 0x93FF5000;
            mlShellCode[85] = 0x401078;
            mlShellCode[86] = 0xFDF0B5FF;
            mlShellCode[87] = 0xFC6AFFFF;
            mlShellCode[88] = 0xFF0875FF;
            mlShellCode[89] = 0x40108893;
            mlShellCode[90] = 0xC0336100;
            mlShellCode[91] = 0xC03303EB;
            mlShellCode[92] = 0xC2C95B40;
            mlShellCode[93] = 0x6B0008;
            mlShellCode[94] = 0x720065;
            mlShellCode[95] = 0x65006E;
            mlShellCode[96] = 0x33006C;
            mlShellCode[97] = 0x2E0032;
            mlShellCode[98] = 0x6C0064;
            mlShellCode[99] = 0x6C;
            mlShellCode[100] = 0x730075;
            mlShellCode[101] = 0x720065;
            mlShellCode[102] = 0x320033;
            mlShellCode[103] = 0x64002E;
            mlShellCode[104] = 0x6C006C;
            mlShellCode[105] = 0x69560000;
            mlShellCode[106] = 0x61757472;
            mlShellCode[107] = 0x6572466C;
            mlShellCode[108] = 0x6C470065;
            mlShellCode[109] = 0x6C61626F;
            mlShellCode[110] = 0x646E6946;
            mlShellCode[111] = 0x6D6F7441;
            mlShellCode[112] = 0x6C470057;
            mlShellCode[113] = 0x6C61626F;
            mlShellCode[114] = 0x41646441;
            mlShellCode[115] = 0x576D6F74;
            mlShellCode[116] = 0x74736C00;
            mlShellCode[117] = 0x706D6372;
            mlShellCode[118] = 0x4F005769;
            mlShellCode[119] = 0x446E6570;
            mlShellCode[120] = 0x746B7365;
            mlShellCode[121] = 0x57706F;
            mlShellCode[122] = 0x6D756E45;
            mlShellCode[123] = 0x6B736544;
            mlShellCode[124] = 0x57706F74;
            mlShellCode[125] = 0x6F646E69;
            mlShellCode[126] = 0x47007377;
            mlShellCode[127] = 0x69577465;
            mlShellCode[128] = 0x776F646E;
            mlShellCode[129] = 0x74786554;
            mlShellCode[130] = 0x65470057;
            mlShellCode[131] = 0x6E695774;
            mlShellCode[132] = 0x4C776F64;
            mlShellCode[133] = 0x57676E6F;
            mlShellCode[134] = 0x74655300;
            mlShellCode[135] = 0x646E6957;
            mlShellCode[136] = 0x6F4C776F;
            mlShellCode[137] = 0x57676E;
            mlShellCode[138] = 0x6C6C6143;
            mlShellCode[139] = 0x646E6957;
            mlShellCode[140] = 0x7250776F;
            mlShellCode[141] = 0x57636F;
            mlShellCode[142] = 0x4C746547;
            mlShellCode[143] = 0x45747361;
            mlShellCode[144] = 0x726F7272;
            mlShellCode[145] = 0x72695600;
            mlShellCode[146] = 0x6C617574;
            mlShellCode[147] = 0x6F6C6C41;
            mlShellCode[148] = 0x8B550063;
            mlShellCode[149] = 0xFCC483EC;
            mlShellCode[150] = 0x48C03360;
            mlShellCode[151] = 0x8DFC4589;
            mlShellCode[152] = 0x40117683;
            mlShellCode[153] = 0x93FF5000;
            mlShellCode[154] = 0x401000;
            mlShellCode[155] = 0x840FC00B;
            mlShellCode[156] = 0xFA;
            mlShellCode[157] = 0x838DF88B;
            mlShellCode[158] = 0x401190;
            mlShellCode[159] = 0x93FF50;
            mlShellCode[160] = 0xB004010;
            mlShellCode[161] = 0xE3840FC0;
            mlShellCode[162] = 0x8B000000;
            mlShellCode[163] = 0x45838DF0;
            mlShellCode[164] = 0x50004012;
            mlShellCode[165] = 0x493FF57;
            mlShellCode[166] = 0x89004010;
            mlShellCode[167] = 0x40107483;
            mlShellCode[168] = 0x38838D00;
            mlShellCode[169] = 0x50004012;
            mlShellCode[170] = 0x493FF57;
            mlShellCode[171] = 0x89004010;
            mlShellCode[172] = 0x40108C83;
            mlShellCode[173] = 0xC2838D00;
            mlShellCode[174] = 0x50004011;
            mlShellCode[175] = 0x493FF57;
            mlShellCode[176] = 0x89004010;
            mlShellCode[177] = 0x40107883;
            mlShellCode[178] = 0xB2838D00;
            mlShellCode[179] = 0x50004011;
            mlShellCode[180] = 0x493FF57;
            mlShellCode[181] = 0x89004010;
            mlShellCode[182] = 0x4013D083;
            mlShellCode[183] = 0xD1838D00;
            mlShellCode[184] = 0x50004011;
            mlShellCode[185] = 0x493FF57;
            mlShellCode[186] = 0x89004010;
            mlShellCode[187] = 0x40107C83;
            mlShellCode[188] = 0xDB838D00;
            mlShellCode[189] = 0x50004011;
            mlShellCode[190] = 0x493FF56;
            mlShellCode[191] = 0x89004010;
            mlShellCode[192] = 0x40109083;
            mlShellCode[193] = 0xE8838D00;
            mlShellCode[194] = 0x50004011;
            mlShellCode[195] = 0x493FF56;
            mlShellCode[196] = 0x89004010;
            mlShellCode[197] = 0x40109483;
            mlShellCode[198] = 0xFB838D00;
            mlShellCode[199] = 0x50004011;
            mlShellCode[200] = 0x493FF56;
            mlShellCode[201] = 0x89004010;
            mlShellCode[202] = 0x40108083;
            mlShellCode[203] = 0xA838D00;
            mlShellCode[204] = 0x50004012;
            mlShellCode[205] = 0x493FF56;
            mlShellCode[206] = 0x89004010;
            mlShellCode[207] = 0x40108483;
            mlShellCode[208] = 0x19838D00;
            mlShellCode[209] = 0x50004012;
            mlShellCode[210] = 0x493FF56;
            mlShellCode[211] = 0x89004010;
            mlShellCode[212] = 0x40108883;
            mlShellCode[213] = 0x28838D00;
            mlShellCode[214] = 0x50004012;
            mlShellCode[215] = 0x493FF56;
            mlShellCode[216] = 0x89004010;
            mlShellCode[217] = 0x4013CC83;
            mlShellCode[218] = 0x89C03300;
            mlShellCode[219] = 0x8B61FC45;
            mlShellCode[220] = 0xC3C9FC45;
            mlShellCode[221] = 0x53EC8B55;
            mlShellCode[222] = 0xE8;
            mlShellCode[223] = 0xEB815B00;
            mlShellCode[224] = 0x40137D;
            mlShellCode[225] = 0x120C7D81;
            mlShellCode[226] = 0x75000003;
            mlShellCode[227] = 0xD4838D1C;
            mlShellCode[228] = 0x50004013;
            mlShellCode[229] = 0x13D093FF;
            mlShellCode[230] = 0xB70F0040;
            mlShellCode[231] = 0x74C00BC0;
            mlShellCode[232] = 0x40C03308;
            mlShellCode[233] = 0x10C2C95B;
            mlShellCode[234] = 0x1475FF00;
            mlShellCode[235] = 0xFF1075FF;
            mlShellCode[236] = 0x75FF0C75;
            mlShellCode[237] = 0xC8B3FF08;
            mlShellCode[238] = 0xFF004013;
            mlShellCode[239] = 0x4013CC93;
            mlShellCode[240] = 0xC2C95B00;
            mlShellCode[241] = 0xFF8B0010;
            mlShellCode[245] = 0x6F0048;
            mlShellCode[246] = 0x6B006F;
            mlShellCode[247] = 0x790053;
            mlShellCode[248] = 0x4B0073;
            mlShellCode[249] = 0x790065;
            mlShellCode[250] = 0x8B550000;
            mlShellCode[251] = 0xD8C481EC;
            mlShellCode[252] = 0xE8FFFFFD;
            mlShellCode[253] = 0x226;
            mlShellCode[254] = 0x8DE84589;
            mlShellCode[255] = 0x6A50EC45;
            mlShellCode[256] = 0xE875FF28;
            mlShellCode[257] = 0x24BE8;
            mlShellCode[258] = 0xFC00B00;
            mlShellCode[259] = 0x11584;
            mlShellCode[260] = 0xF4458D00;
            mlShellCode[261] = 0x20606850;
            mlShellCode[262] = 0x6A0040;
            mlShellCode[263] = 0x22DE8;
            mlShellCode[264] = 0x74C00B00;
            mlShellCode[265] = 0xF045C722;
            mlShellCode[266] = 0x1;
            mlShellCode[267] = 0x2FC45C7;
            mlShellCode[268] = 0x6A000000;
            mlShellCode[269] = 0x6A006A00;
            mlShellCode[270] = 0xF0458D00;
            mlShellCode[271] = 0xFF006A50;
            mlShellCode[272] = 0x1E8EC75;
            mlShellCode[273] = 0xFF000002;
            mlShellCode[274] = 0x6A0875;
            mlShellCode[275] = 0x1F0FFF68;
            mlShellCode[276] = 0x1CEE800;
            mlShellCode[277] = 0x45890000;
            mlShellCode[278] = 0x68046AE8;
            mlShellCode[279] = 0x1000;
            mlShellCode[280] = 0x4F268;
            mlShellCode[281] = 0xFF006A00;
            mlShellCode[282] = 0xC1E8E875;
            mlShellCode[283] = 0x89000001;
            mlShellCode[284] = 0x6AE445;
            mlShellCode[285] = 0x4F268;
            mlShellCode[286] = 0x10006800;
            mlShellCode[287] = 0x75FF0040;
            mlShellCode[288] = 0xE875FFE4;
            mlShellCode[289] = 0x1B9E8;
            mlShellCode[290] = 0x30186800;
            mlShellCode[291] = 0x86A0040;
            mlShellCode[292] = 0x40300068;
            mlShellCode[293] = 0xE475FF00;
            mlShellCode[294] = 0xE8E875FF;
            mlShellCode[295] = 0x1A2;
            mlShellCode[296] = 0x81E4558B;
            mlShellCode[297] = 0x8C2;
            mlShellCode[298] = 0x6A006A00;
            mlShellCode[299] = 0x52006A00;
            mlShellCode[300] = 0x6A006A;
            mlShellCode[301] = 0xE8E875FF;
            mlShellCode[302] = 0x156;
            mlShellCode[303] = 0x144E850;
            mlShellCode[304] = 0x18680000;
            mlShellCode[305] = 0x6A004030;
            mlShellCode[306] = 0x30006808;
            mlShellCode[307] = 0x75FF0040;
            mlShellCode[308] = 0xE875FFE4;
            mlShellCode[309] = 0x151E8;
            mlShellCode[310] = 0x58D00;
            mlShellCode[311] = 0x8B004030;
            mlShellCode[312] = 0x4408B10;
            mlShellCode[313] = 0xCB685250;
            mlShellCode[314] = 0x8D004020;
            mlShellCode[315] = 0xFFFDD885;
            mlShellCode[316] = 0x909050FF;
        }
    }
}