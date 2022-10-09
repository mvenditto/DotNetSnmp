using SnmpDotNet.Client;
using SnmpDotNet.Protocol.V1;
using System.Net;

var get = new SnmpV1Message
{
    Community = "public",
    Pdu = new GetRequestPdu
    {
        VariableBindings = new("1.3.6.1.2.1.1.1.0")
    }
};

var target = new IPEndPoint(IPAddress.Loopback, 161);

using var client = new SnmpUdpClient(target);

var res = await client.GetAsync(get);

foreach (var(name, value) in res.VariableBindings)
{
    Console.WriteLine($"{name}: {value}");
}
