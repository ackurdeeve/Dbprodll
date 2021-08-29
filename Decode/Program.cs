using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Decode
{
    class Program
    {
        static void Main(string[] args)
        {
            string authcode = "568BB8747712C4D314A5842BAF4B47800943B32E781968037577CE6209FA2721776A95B7EFF0B1711866877C215B3C4DAC72020816F60892A778CD7120A8D0FE457AA054335FFBFD4AD1564D5ACCCCFEF9D94E01BA45861783E4ACBE741407B9208CBB23037D41B67CF9DDB81C8D59DB76EA6426928F09E1DE601B093D7AF75B77943425";
            
            string requestcode = "D9C9506090F6A409087D3DCAAD2163B2";
            var test = requestcode.Remove(0,1);

            var authcode_byte = ConvertAuthcodeToChars(authcode);
            var requestcode_byte = ConvertAuthcodeToChars(requestcode);
            var requestcode_ending = DecodeAuthCode(requestcode, 16); //获取机器码后8位,倒过来 D9C9506090F6A409087D3DCAAD2163B22E9701D7

            var authverify = DecodeAuthCode(authcode, 128); //0x25349477
            var verifycode  = GetVerifyCode(authcode);

            string gigabyte_request = "D9C9506090F6A40908C8F341550C1748";
            string gigabyte = "43A3D139F4265F4E95DEEB02FB27441107166B5A04048C28672A09496BFA86ECB1AA4AC4663B2C178E037F19C55AD2FD9FFE4370F27C01A7F7A8D39C80570C362A0358F46C364C140C7569D8E872FD312EEBDABC7C74B4F38106C0828FB6582EA78BCE8D70F57B1D482F16E8FC5E9412CFDA561CD63FB8A0722CA6D408CB2932D38E09D5";
            
            var giga_request_ending =  DecodeAuthCode(gigabyte_request, 16);
            
            var gigaauthverify = DecodeAuthCode(gigabyte, 128);
            var gigaverifycode  = GetVerifyCode(gigabyte);

            var outbuffer = new uint[128]; //0000000000AFCBF0
            
            for (int i = 0; i < 8; i++)
            {
                var updateAuth = new uint[15];
                var result = VerifyAuthCode(authcode,out updateAuth);
                var index = i *16;
                for (int j = 0; j < 16; j++)
                {
                    outbuffer[j+index] = updateAuth[j];
                }
                authcode = authcode.PadLeft(32).Remove(0, 32);
                Console.WriteLine("{0:X4}",result);
            }
            
            var outbuffer1 = new uint[128];
            
            for (int i = 0; i < 8; i++)
            {
                var updateAuth = new uint[15];
                var result = VerifyAuthCode(gigabyte,out updateAuth);
                var index = i *16;
                for (int j = 0; j < 16; j++)
                {
                    outbuffer1[j+index] = updateAuth[j];
                }
                authcode = authcode.PadLeft(32).Remove(0, 32);
                Console.WriteLine("{0:X4}",result);
            }
            
            
            Console.WriteLine(authcode.Length);
        }
        
        public static uint GetVerifyCode(string authcode)
        {
            var vericode = authcode.Substring(authcode.Length-8,8);
            var vericode_byte = ConvertAuthcodeToChars(vericode);
            var code = (vericode_byte[3] << 24) + (vericode_byte[2] << 16) + (vericode_byte[1] << 8) + vericode_byte[0];
            return code;
        }

        public static uint[] ConvertAuthcodeToChars(string authcode)
        {
            var length = authcode.Length;
            var bytecount = Convert.ToInt32(length * 0.5);
            var authbyte = new uint[bytecount];
            int count = 0;
            for (int i = 0; i < bytecount; i++)
            {
                authbyte[i] = (char)Int32.Parse(authcode.Substring(count, 2), NumberStyles.HexNumber);
                count = count + 2;
            }

            return authbyte;
        }

        //注册码解码算法1
        public static ulong DecodeAuthCode(string authcode, int length)
        {
            uint v2 = 0xFFFFFFFF;
            var authcode_byte = ConvertAuthcodeToChars(authcode);
            for (int i = 0; i < length; i++)
            {
                var v5 = authcode_byte[i];
                var index = (v2 ^ v5) & 0xff; //sbyte
                var dparse = decodetable[index];
                var v3 = v2 >> 8;
                v2 = v3 ^ dparse;
            }
            return ~v2;
        }

        // a1 authcode_byte; a3 verifytable; a2 需要修改的authocodebyte
        //uint a1, uint a2, ulong a3,  not used
        //rcx,rdx,r8 
        //r8 authcode rcx = rdx 均为注册码的首地址
        //每16个key循环更新 一共更新9次
        public static uint VerifyAuthCode(string authcode, out uint[] authcode_bytebuffer)
        {
            var authcode_byte = ConvertAuthcodeToChars(authcode);
            var verifytable_index = 2; ////00007FFF662B43E8
            var v6 = (((authcode_byte[3] << 8 | authcode_byte[2]) << 8) | authcode_byte[1]) << 8 | authcode_byte[0];
            var v8 = (((authcode_byte[11] << 8 | authcode_byte[10]) << 8) | authcode_byte[9]) << 8 |
                     authcode_byte[8]; //0x2B84A514
            var v9 = verifytable[0] + (((((authcode_byte[7] << 8 | authcode_byte[6]) << 8) | authcode_byte[5]) << 8) |
                                       authcode_byte[4]); //0000000016CF169B
            var v10 = verifytable[1] +
                      (((((authcode_byte[15] << 8 | authcode_byte[14]) << 8) | authcode_byte[13]) << 8) |
                       authcode_byte[12]); //0x00000000F74CA19D;
            uint v5 = 2;
            uint v11 = 0;
            uint v12 = 0;
            uint v13 = 0;
            uint v14; // edx
            uint v15; // r8
            uint v16; // edx
            uint v17; // edx
            uint result; // rax
            uint v19; // ebx
            uint v20; // er11

            var v7 = 20;
            do
            {
                v5 = v5 + 2;
                var test = v9 * (2 * v9 + 1);
                //0x80211A4D
                //10000000001000010001101001001101
                v11 = Rollbit(v9 * (2 * v9 + 1), 5, true);
                //0x2D9E2D37
                //00101101100111100010110100110111
                v12 = v11 & 0xff;
                v13 = v6 ^ v11;
                v6 = v9;
                v14 = Rollbit(v10 * (v10 * 2 + 1), 5, true);
                v15 = v14 & 0x1f;
                v16 = v8 ^ v14;
                v8 = v10;
                // test = Rollbit(v16, (int)v12&0x1f, true);
                v17 = verifytable[v5 - 1] + Rollbit(v16, (int)v12 & 0x1f, true);
                result = verifytable[v5 - 2] + Rollbit(v13, (int)v15, true);
                v9 = v17;
                v10 = result;
                --v7;
            } while (v7 > 0);

            v19 = verifytable[43] + v8; //00000000772CB6CE
            v20 = verifytable[42] + v6; //00000000276374F1
            
            authcode_bytebuffer = new uint[16];
            authcode_bytebuffer[8] = v19 & 0xff;
            authcode_bytebuffer[0] = v20 & 0xff; //BYTE
            authcode_bytebuffer[3] = (v20 & 0xff000000) >> 24; //HIBYTe
            authcode_bytebuffer[4] = v17 & 0xff; //BYTE
            authcode_bytebuffer[12] = result & 0xff;
            authcode_bytebuffer[2] = (v20 & 0x00ff0000) >> 16; //BYTE2
            authcode_bytebuffer[1] = (v20 & 0xff00) >> 8; //BYTE1
            authcode_bytebuffer[7] = (v17 & 0xff000000) >> 24; //HIBYTE
            authcode_bytebuffer[6] = (v17 & 0x00ff0000) >> 16; //BYTE2
            authcode_bytebuffer[5] = (v17 & 0xff00) >> 8; //BYTE1
            authcode_bytebuffer[11] = (v19 & 0xff000000) >> 24; //HIBYTe
            authcode_bytebuffer[10] = (v19 & 0x00ff0000) >> 16; //BYTE2
            authcode_bytebuffer[9] = (v19 & 0xff00) >> 8; //BYTE1
            authcode_bytebuffer[15] = (result & 0xff000000) >> 24; //HIBYTE,BYTE3,00000000A80EEFCA
            authcode_bytebuffer[14] = (result & 0x00ff0000) >> 16; //BYTE2
            authcode_bytebuffer[13] = (result & 0xff00) >> 8; //BYTE1
            return result;
        }

        static uint Rollbit(uint val, int iShiftBit, bool isLeft)
        {
            uint temp = 0;
            uint result = 0;
            temp |= val;
            if (isLeft)
            {
                val <<= iShiftBit;
                temp >>= (32 - iShiftBit);
                result = val | temp;
            }
            else
            {
                val >>= iShiftBit;
                temp >>= (32 - iShiftBit);
                result = val | temp;
            }

            return result;
        }

        //for authorization
        static uint[] decodetable =
        {
            0x0, 0x77073096, 0x0EE0E612C, 0x990951BA, 0x76DC419, 0x706AF48F, 0x0E963A535,
            0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0x0E0D5E91E, 0x97D2D988, 0x9B64C2B, 0x7EB17CBD,
            0x0E7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2, 0x0F3B97148, 0x84BE41DE,
            0x1ADAD47D, 0x6DDDE4EB, 0x0F4D4B551, 0x83D385C7, 0x136C9856, 0x646BA8C0, 0x0FD62F97A,
            0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0x0FA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E,
            0x0D56041E4, 0x0A2677172, 0x3C03E4D1, 0x4B04D447, 0x0D20D85FD, 0x0A50AB56B,
            0x35B5A8FA, 0x42B2986C, 0x0DBBBC9D6, 0x0ACBCF940, 0x32D86CE3, 0x45DF5C75,
            0x0DCD60DCF, 0x0ABD13D59, 0x26D930AC, 0x51DE003A, 0x0C8D75180, 0x0BFD06116,
            0x21B4F4B5, 0x56B3C423, 0x0CFBA9599, 0x0B8BDA50F, 0x2802B89E, 0x5F058808,
            0x0C60CD9B2, 0x0B10BE924, 0x2F6F7C87, 0x58684C11, 0x0C1611DAB, 0x0B6662D3D,
            0x76DC4190, 0x1DB7106, 0x98D220BC, 0x0EFD5102A, 0x71B18589, 0x6B6B51F, 0x9FBFE4A5,
            0x0E8B8D433, 0x7807C9A2, 0x0F00F934, 0x9609A88E, 0x0E10E9818, 0x7F6A0DBB,
            0x86D3D2D, 0x91646C97, 0x0E6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0x0F262004E,
            0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0x0F50FC457, 0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA,
            0x0FCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0x0FBD44C65, 0x4DB26158,
            0x3AB551CE, 0x0A3BC0074, 0x0D4BB30E2, 0x4ADFA541, 0x3DD895D7, 0x0A4D1C46D,
            0x0D3D6F4FB, 0x4369E96A, 0x346ED9FC, 0x0AD678846, 0x0DA60B8D0, 0x44042D73,
            0x33031DE5, 0x0AA0A4C5F, 0x0DD0D7CC9, 0x5005713C, 0x270241AA, 0x0BE0B1010,
            0x0C90C2086, 0x5768B525, 0x206F85B3, 0x0B966D409, 0x0CE61E49F, 0x5EDEF90E,
            0x29D9C998, 0x0B0D09822, 0x0C7D7A8B4, 0x59B33D17, 0x2EB40D81, 0x0B7BD5C3B,
            0x0C0BA6CAD, 0x0EDB88320, 0x9ABFB3B6, 0x3B6E20C, 0x74B1D29A, 0x0EAD54739,
            0x9DD277AF, 0x4DB2615, 0x73DC1683, 0x0E3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
            0x0E40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1, 0x0F00F9344, 0x8708A3D2,
            0x1E01F268, 0x6906C2FE, 0x0F762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7, 0x0FED41B76,
            0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0x0F9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
            0x0D6D6A3E8, 0x0A1D1937E, 0x38D8C2C4, 0x4FDFF252, 0x0D1BB67F1, 0x0A6BC5767,
            0x3FB506DD, 0x48B2364B, 0x0D80D2BDA, 0x0AF0A1B4C, 0x36034AF6, 0x41047A60,
            0x0DF60EFC3, 0x0A867DF55, 0x316E8EEF, 0x4669BE79, 0x0CB61B38C, 0x0BC66831A,
            0x256FD2A0, 0x5268E236, 0x0CC0C7795, 0x0BB0B4703, 0x220216B9, 0x5505262F,
            0x0C5BA3BBE, 0x0B2BD0B28, 0x2BB45A92, 0x5CB36A04, 0x0C2D7FFA7, 0x0B5D0CF31,
            0x2CD99E8B, 0x5BDEAE1D, 0x9B64C2B0, 0x0EC63F226, 0x756AA39C, 0x26D930A, 0x9C0906A9,
            0x0EB0E363F, 0x72076785, 0x5005713, 0x95BF4A82, 0x0E2B87A14, 0x7BB12BAE, 0x0CB61B38,
            0x92D28E9B, 0x0E5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0x0F1D4E242,
            0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0x0F6B9265B, 0x6FB077E1, 0x18B74777, 0x88085AE6,
            0x0FF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0x0F862AE69, 0x616BFFD3,
            0x166CCF45, 0x0A00AE278, 0x0D70DD2EE, 0x4E048354, 0x3903B3C2, 0x0A7672661,
            0x0D06016F7, 0x4969474D, 0x3E6E77DB, 0x0AED16A4A, 0x0D9D65ADC, 0x40DF0B66,
            0x37D83BF0, 0x0A9BCAE53, 0x0DEBB9EC5, 0x47B2CF7F, 0x30B5FFE9, 0x0BDBDF21C,
            0x0CABAC28A, 0x53B39330, 0x24B4A3A6, 0x0BAD03605, 0x0CDD70693, 0x54DE5729,
            0x23D967BF, 0x0B3667A2E, 0x0C4614AB8, 0x5D681B02, 0x2A6F2B94, 0x0B40BBE37,
            0x0C30C8EA1, 0x5A05DF1B, 0x2D02EF8D
        };

        //for verify
        private static uint[] verifytable =
        {
            0x430B0424, 0x770555EE, 0x6EAB1B27, 0x0CC5EE445, 0x5C6FD2A2, 0x0EB7ABADF,
            0x0F12E45D9, 0x28FD8500, 0x818909D9, 0x5E595615, 0x0DD162796, 0x0CAFAB96D,
            0x592A7792, 0x0FE029FAF, 0x5A67D287, 0x0F8D84636, 0x0F6B89EF1, 0x0E1DC9E03,
            0x0C5158DAB, 0x16A53626, 0x27C6EC59, 0x0CA6C910A, 0x72AFDC8B, 0x2E92A3D6,
            0x3BED21B0, 0x9367E29D, 0x25F87C05, 0x4D358806, 0x776F31CB, 0x0A9478F82, 0x0D7702627,
            0x828DB79, 0x0F0146E7C, 0x3AAC3EDC, 0x67902059, 0x989D2CA7, 0x4F95E7CF, 0x485A06C0,
            0x0FFD3F152, 0x58E1D08F, 0x7DC9DB25, 0x0F395C849, 0x0C645D928, 0x62ACD298
        };
        

        [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl")]
        public static extern int DeviceIoControl(
            int hDevice,
            int dwIoControlCode,
            ref int lpInBuffer,
            int nInBufferSize,
            ref int lpOutBuffer,
            int nOutBufferSize,
            ref int lpBytesReturned,
            ref int lpOverlapped
        );

        #region oldcode
        // var lpOverlaped = 0;
        // var nInBuffersize = 0x80;
        // var lpBytesReturned = 0x30;
        // var nOutBufferSize = 0x80;
        // var lpInBuffer = 0xAA;
        // var lpOutBuffer = 0x80;
        //
        // DeviceIoControl(0x7c4, 0x240033, ref outbuffer, nInBuffersize, ref outbuffer, nOutBufferSize, ref lpBytesReturned, ref lpOverlaped);
        
        // a1-rcx 34 指向注册码首地址的指针 a2-rdx  10E 注册码 a3-er8 110 key的数量
        // public static uint Cal24349477(string authcode)
        // {
        //     var authcode_pbyte = Encoding.UTF8.GetBytes(authcode);
        //     byte[] outbuffer = new byte[128]; //需转换每个字符，不是每隔2个
        //     var a2 = authcode_pbyte.Length;
        //
        //     int v3 = 0;
        //     ; // er10
        //     uint v6 = 0;
        //     ; // r9
        //     int v7 = 0; // edi
        //     uint v8 = 0;
        //     ; // rbx
        //     uint v9 = 0;
        //     ; // cl
        //     int v10 = 0;
        //     ; // rdx
        //     uint v11 = 0;
        //     ; // al
        //     uint v12 = 0;
        //     ; // rdx
        //     uint v13 = 0;
        //     ; // cl
        //     uint v14 = 0;
        //     ; // cl
        //     uint v15 = 0;
        //     ; // cl
        //
        //     v3 = 0;
        //     v6 = 0;
        //
        //     if (a2 > 0)
        //     {
        //         v7 = 0;
        //         v8 = 0;
        //         do
        //         {
        //             while (true)
        //             {
        //                 v9 = authcode_pbyte[v8 + v6];
        //                 v10 = authcode_pbyte[v8 + v6];
        //                 if ((0xff & (v9 - 48)) <= 9 || (0xff &(v9 - 97)) <= 5 || (0xff &(v9 - 65)) <= 5) break;
        //                 ++v3;
        //                 ++v6;
        //             }
        //
        //             if ((v9 - 48) <= 9) 
        //                 authcode_pbyte[0] = (byte)(16 * v9);
        //             if ((v10 - 65) <= 5) 
        //                 authcode_pbyte[0] = (byte)(16 * (v10 - 7));
        //             if ((v10 - 97) <= 5) 
        //                 authcode_pbyte[0] = (byte)(16 * (v10 - 7));
        //
        //             while (true)
        //             {
        //                 v11 = authcode_pbyte[v8 + v6 + 1];
        //                 if ((0xff & (v11 - 48)) <= 9 || (0xff &(v11 - 97)) <= 5 || (0xff &(v11- 65)) <= 5) break;
        //                 ++v3;
        //                 ++v6;
        //             }
        //
        //             int index = 0;
        //             v12 = v8 + v6;
        //             v13 = authcode_pbyte[v8 + v6 + 1];
        //             if ((v13 - 48) <= 9) 
        //                 authcode_pbyte[index] += (byte)(v13 & 0xf);
        //             v14 = authcode_pbyte[v12 + 1];
        //             if ((v14 - 65) <= 5) 
        //                 authcode_pbyte[index] += (byte)((v14 - 7) & 0xf);
        //             v15 = authcode_pbyte[v12 + 1];
        //             if ((v15 - 97) <= 5) 
        //                 authcode_pbyte[index] += (byte)((v15 - 7) & 0xf);
        //             v7 += 2;
        //             v8 += 2;
        //             
        //             ++index;
        //         } while (v7 + v3 < a2);
        //     }
        //
        //     return 1;
        // }
        
        // public static string PreprocessingAuthcode(string authcode)
        // {
        //     int i = 0;
        //     var processedAuthcode = DeleteLetters(authcode,authcode.Length);
        //     
        //    string DeleteLetters(string code,int count)
        //     {
        //         var authcode_pbyte = Encoding.UTF8.GetBytes(code);
        //         var processedAuthcode = code;
        //
        //         for (int i = 0; i < authcode_pbyte.Length; i++)
        //         {
        //             var charnum = authcode_pbyte[i];
        //             if (charnum < 48 || (charnum > 57 && charnum < 65) || charnum > 90)
        //             {
        //                 processedAuthcode = processedAuthcode.Remove(i, 1);
        //                 processedAuthcode =DeleteLetters(processedAuthcode,count);
        //             }
        //             count--;
        //             if (count < 0)  return processedAuthcode;
        //         }
        //         return processedAuthcode;
        //     }
        //
        //     return processedAuthcode;
        // }
        #endregion
        
    }
}