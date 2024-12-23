using System;
using System.Collections;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Management.Infrastructure;

namespace Oem_Check
{
    internal class Program
    {
        [DllImport("kernel32")]
        private static extern uint EnumSystemFirmwareTables(uint FirmwareTableProviderSignature, IntPtr pFirmwareTableBuffer, uint BufferSize);
        [DllImport("kernel32")]
        private static extern uint GetSystemFirmwareTable(uint FirmwareTableProviderSignature, uint FirmwareTableID, IntPtr pFirmwareTableBuffer, uint BufferSize);

        private delegate uint GetterDlg(IntPtr pFirmwareTableBuffer, uint BufferSize);
        private static byte[] GetDataHelper(GetterDlg getter)
        {
            uint bSize = getter(IntPtr.Zero, 0);
            IntPtr FirmwareTableBuffer = Marshal.AllocHGlobal((int)bSize);
            var buffer = new byte[bSize];
            getter(FirmwareTableBuffer, bSize);
            Marshal.Copy(FirmwareTableBuffer, buffer, 0, buffer.Length);
            Marshal.FreeHGlobal(FirmwareTableBuffer);
            return buffer;
        }

        private static string ByteToHex(byte[] b, int index, int count)
        {
            string s = string.Empty;

            for (int i = 1; i <= count; i++)
            {
                s += string.Format("{0:X}", b[index + count - i]);
            }
            return $"0x{s}";
        }

        static bool debug = false;
        static void Main(string[] args)
        {
            foreach (string arg in args)
            {
                if (arg.ToLower() == "--debug")
                {
                    debug = true;
                }
            }

            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            var (type, value) = ReadAcpi();
            var key = GetKey();

            Hashtable[] hashtables = GetWmiInfo(@"root\cimv2", "SELECT * FROM Win32_OperatingSystem");

            Console.WriteLine("=========== 系统基本信息 ==============");

            Console.WriteLine(Al($"系统名称：{hashtables[0]["Caption"]}"));
            Console.WriteLine(Al($"系统版本号：{hashtables[0]["Version"]}"));
            Console.WriteLine(Al($"内部版本号：{hashtables[0]["BuildNumber"]}"));
            Console.WriteLine(Al($"系统位宽：{hashtables[0]["OSArchitecture"]}"));
            Console.WriteLine(Al($"系统目录：{hashtables[0]["WindowsDirectory"]}"));
            Console.WriteLine(Al($"计算机名：{hashtables[0]["CSName"]}"));

            Console.WriteLine("=========== 系统激活信息 ==============");

            Console.WriteLine(Al($"产品ID：{hashtables[0]["SerialNumber"]}"));
            Console.WriteLine(Al($"授权版本：{key.version}"));
            Console.WriteLine(Al($"销售渠道：{key.type}"));
            Console.WriteLine(Al($"激活渠道：{key.activation}"));


            Console.WriteLine(Al($"系统密钥：{key.key}"));
            Console.WriteLine(Al($"OEM密钥：{value}"));
            Console.WriteLine(Al($"OEM表：{type}"));


            Console.WriteLine();
            Console.Write("按任意键退出！");
            Console.ReadKey();

        }


        private static void WriteConsole(object str)
        {
            if (debug) Console.WriteLine(str);
        }

        private static (string type, string value) ReadAcpi()
        {
            const uint firmwareTableProvider = 'A' << 24 | 'C' << 16 | 'P' << 8 | 'I';
            var buffer = GetDataHelper((p, s) => EnumSystemFirmwareTables(firmwareTableProvider, p, s));
            string str = Encoding.ASCII.GetString(buffer);
            string type = string.Empty;
            string value = string.Empty;
            for (int i = 0; i <= str.Length - 1; i += 4)
            {
                string tableName = str.Substring(i, 4);
                WriteConsole(tableName);
                if (tableName == "MSDM" || tableName == "SLIC")
                {
                    WriteConsole($"==========={tableName}==============");
                    uint firmwareTableMsdm = 0;
                    if (tableName == "MSDM") firmwareTableMsdm = 'M' << 24 | 'D' << 16 | 'S' << 8 | 'M';
                    if (tableName == "SLIC") firmwareTableMsdm = 'S' << 24 | 'L' << 16 | 'I' << 8 | 'C';
                    buffer = GetDataHelper((p, s) => GetSystemFirmwareTable(firmwareTableProvider, firmwareTableMsdm, p, s));
                    string table = string.Empty;
                    if (tableName == "MSDM")
                    {
                        type = tableName;
                        table += $"Signature:{Encoding.UTF8.GetString(buffer, 0, 4)}<{Environment.NewLine}";
                        table += $"Length:{Convert.ToInt32(ByteToHex(buffer, 4, 4), 16)}<{Environment.NewLine}";
                        table += $"Revision:{ByteToHex(buffer, 8, 1)}<{Environment.NewLine}";
                        table += $"Checksum:{ByteToHex(buffer, 9, 1)}<{Environment.NewLine}";
                        table += $"OEMID:{Encoding.UTF8.GetString(buffer, 10, 6)}<{Environment.NewLine}";
                        table += $"OEM Table ID:{Encoding.UTF8.GetString(buffer, 16, 8)}<{Environment.NewLine}";
                        table += $"OEM Revision:{ByteToHex(buffer, 24, 4)}<{Environment.NewLine}";
                        table += $"Creator ID:{Encoding.UTF8.GetString(buffer, 28, 4)}<{Environment.NewLine}";
                        table += $"Creator Revision:{ByteToHex(buffer, 32, 4)}<{Environment.NewLine}";
                        table += $"SLS Data Version:{ByteToHex(buffer, 36, 8)}<{Environment.NewLine}";
                        table += $"SLS Data Type:{ByteToHex(buffer, 44, 8)}<{Environment.NewLine}";
                        table += $"SLS Data Length:{Convert.ToInt32(ByteToHex(buffer, 52, 4), 16)}<{Environment.NewLine}";
                        value = Encoding.UTF8.GetString(buffer, 56, 29);
                        table += $"SLS Data:{value}<{Environment.NewLine}";
                        WriteConsole(table);

                        string hex = string.Empty;
                        int lineNo = 1;
                        for (int m = 1; m < buffer.Length; m++)
                        {
                            int rnd = m % 8;
                            if (rnd == 1)
                            {
                                hex += $"\t{lineNo,4}\t";
                                lineNo++;
                            }

                            hex += string.Format("{0:x}", buffer[m - 1]).PadLeft(2, '0') + (rnd == 0 ? Environment.NewLine : " ");
                        }
                        WriteConsole(hex);
                    }
                    if (tableName == "SLIC")
                    {
                        WriteConsole(buffer.Length);
                        string hex = string.Empty;
                        int lineNo = 1;
                        for (int m = 1; m < buffer.Length; m++)
                        {
                            int rnd = m % 8;
                            if (rnd == 1)
                            {
                                hex += $"\t{lineNo,4}\t";
                                lineNo++;
                            }

                            hex += string.Format("{0:x}", buffer[m - 1]).PadLeft(2, '0') + (rnd == 0 ? Environment.NewLine : " ");
                        }
                        WriteConsole(hex);
                    }

                    WriteConsole(Encoding.ASCII.GetString(buffer, 0, buffer.Length));
                    WriteConsole($"====================================");
                }

            }

            return (type, value);
        }


        private static (string key, string version, string type, string activation) GetKey()
        {
            int start = Environment.Is64BitOperatingSystem ? 808 : 52;
            string keyName = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
            string valueName = Environment.Is64BitOperatingSystem ? "DigitalProductId4" : "DigitalProductId";
            RegistryView registryView = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32;
            WriteConsole($"读取注册表：{RegistryHive.LocalMachine}\\{keyName}\\{valueName}");
            byte[] pidBuffer = GetRegistryKeyValue(RegistryHive.LocalMachine, keyName, valueName, registryView);



            if (pidBuffer?.Length <= 0)
            {
                WriteConsole("密钥数据读取失败！");
                Console.Write("按任意键退出");
                Console.ReadKey();
                Environment.Exit(0);
            }

            string hex = string.Empty;
            int lineNo = 1;
            for (int m = 1; m < pidBuffer!.Length; m++)
            {
                int rnd = m % 8;
                if (rnd == 1)
                {
                    hex += $"\t{lineNo,4}\t";
                    lineNo++;
                }

                hex += string.Format("{0:x}", pidBuffer[m - 1]).PadLeft(2, '0') + (rnd == 0 ? Environment.NewLine : " ");
            }
            WriteConsole(hex);




            WriteConsole($"已获取到已加密的Windows密钥和激活数据，数据长度：{pidBuffer.Length} 字节");
            WriteConsole($"尝试解密数据...");
            return DecodeProductKey(pidBuffer, start);

        }

        private static byte[] GetRegistryKeyValue(RegistryHive regHive, string keyName, string valueName, RegistryView rv)
        {
            RegistryKey baseKey = RegistryKey.OpenBaseKey(regHive, rv);
            RegistryKey rk = baseKey.OpenSubKey(keyName, false)!;
            byte[] data = (byte[])rk.GetValue(valueName)!;
            return data;
        }

        private static (string key, string version, string type, string activation) DecodeProductKey(byte[] digitalProductId, int keyStartIndex)
        {
            string version = string.Empty;
            string type = string.Empty;
            string activation = string.Empty;

            WriteConsole($"起始字节偏移量：{keyStartIndex}");
            char[] digits = new char[] { 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y', '2', '3', '4', '6', '7', '8', '9' };

            const int decodeLength = 29;
            const int decodeStringLength = 15;
            const int numLetters = 24;
            WriteConsole($"解密字节长度：{decodeLength}");
            WriteConsole($"解密字符串长度：{decodeStringLength}");

            char[] decodedChars = new char[decodeLength];

            int keyEndIndex = keyStartIndex + 15;
            WriteConsole($"结尾字节偏移量：{keyEndIndex}");
            int containsN = (digitalProductId[keyStartIndex + 14] >> 3) & 1;
            WriteConsole($"标记位移位结果：{containsN}");
            digitalProductId[keyStartIndex + 14] = (byte)((digitalProductId[keyStartIndex + 14] & 0xF7) | ((containsN & 2) << 2));
            WriteConsole($"标记位修正结果：0x{digitalProductId[keyStartIndex + 14]:X}");
            WriteConsole($"开始解密...");
            List<byte> hexPid = new();
            for (int i = keyStartIndex; i <= keyEndIndex; i++)
            {
                hexPid.Add(digitalProductId[i]);
            }
            for (int i = decodeLength - 1; i >= 0; i--)
            {
                if ((i + 1) % 6 == 0)
                {
                    decodedChars[i] = '-';
                }
                else
                {
                    int digitMapIndex = 0;
                    for (int j = decodeStringLength - 1; j >= 0; j--)
                    {
                        int byteValue = (digitMapIndex << 8) | hexPid[j];
                        hexPid[j] = (byte)(byteValue / numLetters);
                        digitMapIndex = byteValue % numLetters;
                        decodedChars[i] = digits[digitMapIndex];
                    }
                }
            }

            string key = new(decodedChars);


            if (containsN != 0)
            {
                WriteConsole($"标记位数据存在，需要修正已解密的原始密钥key数据：{key.Replace("-", "")}");
                int firstLetterIndex = 0;
                for (int index = 0; index < numLetters; index++)
                {
                    if (decodedChars[0] != digits[index]) continue;
                    firstLetterIndex = index;
                    break;
                }
                string keyWithN = new(decodedChars);

                keyWithN = keyWithN.Replace("-", string.Empty).Remove(0, 1);
                keyWithN = string.Concat(keyWithN.AsSpan(0, firstLetterIndex), "N", keyWithN.Remove(0, firstLetterIndex));
                keyWithN = $"{keyWithN[..5]}-{keyWithN.Substring(5, 5)}-{keyWithN.Substring(10, 5)}-{keyWithN.Substring(15, 5)}-{keyWithN.Substring(20, 5)}";

                key = keyWithN;
            }
            WriteConsole($"已解密密钥数据，密钥Key：{key}");

            WriteConsole($"从原始数据中获取到的其他相关数据：");
            int m = 7;
            try
            {
                byte[] versionArray = new byte[128];
                Buffer.BlockCopy(digitalProductId, 280, versionArray, 0, 128);
                version = Encoding.Unicode.GetString(versionArray).Replace("\0", "");
                WriteConsole($"授权版本：{version}");
            }
            catch
            {
                m -= 1;
            }
            try
            {
                byte[] typeArray = new byte[128];
                Buffer.BlockCopy(digitalProductId, 1016, typeArray, 0, 128);
                type = Encoding.Unicode.GetString(typeArray).Replace("\0", "");
                WriteConsole($"销售渠道：{type}");
            }
            catch
            {
                m -= 2;
            }
            try
            {
                byte[] activationArray = new byte[128];
                Buffer.BlockCopy(digitalProductId, 1144, activationArray, 0, 128);
                activation = Encoding.Unicode.GetString(activationArray).Replace("\0", "");
                WriteConsole($"激活渠道：{activation}");
            }
            catch
            {
                m -= 4;
            }
            if (m <= 0)
            {
                WriteConsole($"无其他信息...");
            }
            return (key, version, type, activation);
        }

        private static Hashtable[] GetWmiInfo(string wmiScope, string classQuery)
        {
            CimSession cimSession = CimSession.Create(null);

            IEnumerable<CimInstance> queryInstances = cimSession.QueryInstances(wmiScope, "WQL", classQuery);

            List<Hashtable> hashtables = new();
            foreach (CimInstance m in queryInstances)
            {
                Hashtable hashtable = new();
                foreach (var p in m.CimInstanceProperties)
                {
                    hashtable.Add(p.Name, p.Value);
                }
                hashtables.Add(hashtable);
            }
            return hashtables.ToArray();
        }

        private static string Al(string str)
        {
            if (str.IndexOf("：") < 0) return str;
            string[] temp = str.Split('：');

            Encoding coding = Encoding.GetEncoding("GB2312");
            int dcount = 0;
            foreach (char ch in temp[0].ToCharArray())
            {
                if (coding.GetByteCount(ch.ToString()) == 2)
                {
                    dcount++;
                }
            }

            string w = temp[0].PadRight(22 - dcount, ' ');

            return $"{w}:\t{temp[1]}";
        }
    }
}