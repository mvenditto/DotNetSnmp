using SnmpDotNet.Client;
using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Protocol.V1;
using SnmpDotNet.Transport;
using SnmpDotNet.Transport.Targets;
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
        VariableBindings = new("1.3.6.1.2.1.1.1.0")
    }
) as GetResponsePdu;

Console.WriteLine(response?.VariableBindings.First());