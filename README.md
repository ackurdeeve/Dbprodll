# Dbprodll
DongleBackupPro Algorithm 

## Environment

1. Get vs2019 community, double-click DbproAlgro.sln to open the code.
2. If you like, you can also download [IDA free](https://hex-rays.com/ida-free) to explore the DBPRO.dll(in folder "dbpro") and debug to see the algrothm.
- new-> open dbpro.dll, and choose donglebackup_pro to debug in IDA.
- download [x64dbg](https://sourceforge.net/projects/x64dbg/files/snapshots/) to help with your debug work.

## Codes

I have worked to partially understand the algorithm of this software. I think the key is to install the virtual dongle.

Drive is installed in the UI does not mean you actually successfully install the dongle. In other words, 
you must see "Safenet USB Superpro/Ultrapro" like content in USB device list.

Do not need to see the donglebackuppro.exe, it is just a UI to communicate with the background functions coded in dbpro.dll.

1. Request generate code 

```c#
 string requestcode = "D9C9506090F6A409087D3DCAAD2163B2";  // computer based label
 var requestcode_ending = DecodeAuthCode(requestcode, 16);  // 2E9701D7
```
The request code is calculated use the DecodeAuthCode function. After you run this code, you will get the last 8 bytes of the request code. 
You have to concate them to the fullcode like "D9C9506090F6A409087D3DCAAD2163B22E9701D7".

2. Verify code
```c#
string authcode = "568BB8747712C4D314A5842BAF4B47800943B32E781968037577CE6209FA2721776A95B7EFF0B1711866877C215B3C4DAC72020816F60892A778CD7120A8D0FE457AA054335FFBFD4AD1564D5ACCCCFEF9D94E01BA45861783E4ACBE741407B9208CBB23037D41B67CF9DDB81C8D59DB76EA6426928F09E1DE601B093D7AF75B77943425";
var authverify = DecodeAuthCode(authcode, 128); //0x25349477
var verifycode  = GetVerifyCode(authcode); //0x25349477
```
verifycode gets the last 8 bytes of the authocode. authverify verify the whole authcode from the beginning to the 128 byte to get a result.
The result must be the same with the verifycode.

3. Decode all authcode

I do not know what authcode after 128 bytes are used for. But I see it is all decoded and save to outbuffer using the below code.

```c#
var outbuffer = new uint[128];
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
```

I have also noticed that some of the decoded bytes are used in [DeviceIoControl api](https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol).

It is the communication mechanical between the driver and the software. It needs some windows driver development experience to fully understand the code. 

The work is not done. I can not garrant the work could be done. It is welcome that anyone can help.
