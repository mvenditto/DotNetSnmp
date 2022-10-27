using DotNetSnmp.Client;
using DotNetSnmp.Common.Definitions;
using DotNetSnmp.Protocol.V1;
using DotNetSnmp.Transport;
using DotNetSnmp.Transport.Targets;
using System.Net;

var target = new IPEndPoint(
    IPAddress.Parse("127.0.0.1"), 161);

var dispatcher = new SnmpDispatcher();

var response = await dispatcher.SendPdu(
    new BasicUdpTransport(target),
    new CommunityTarget("public")
    {
        ProtocolVersion = ProtocolVersion.SnmpV1
    },
    target,
    new GetRequestPdu()
    {
        VariableBindings = new(
            "1.3.6.1.2.1.1.1.0", // sysDescr
            "1.3.6.1.2.1.1.3.0"  // sysUptime
        )
    }
) as GetResponsePdu;

foreach(var varBind in response.VariableBindings)
{
    Console.WriteLine(varBind);
}