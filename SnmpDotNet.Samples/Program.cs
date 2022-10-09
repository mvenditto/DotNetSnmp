using SnmpDotNet.Client;
using SnmpDotNet.Protocol.V1;
using SnmpDotNet.Protocol.V3;
using SnmpDotNet.Protocol.V3.Security;
using SnmpDotNet.Protocol.V3.Security.Authentication;
using SnmpDotNet.Protocol.V3.Security.Privacy;
using System.Net;
using System.Text;
/*
var privKey = new byte[16];

for (var i = 0; i < 16; i++)
{
    privKey[i] = (byte) i;
}

var des = new DESPrivacyService(privKey, 42);

var test = "TESTTESTTEST";

var x = Encoding.UTF8.GetBytes(test);

var privParams = new byte[8];

var encrypted = new byte[16];

var ou = "Gfntz3qZmOXkc4+4ezyQNA==";

var result = des.EncryptScopedPdu(x, privParams, encrypted);

Console.WriteLine(Convert.ToBase64String(encrypted));*/