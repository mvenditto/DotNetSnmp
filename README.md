# DotNetSnmp
[![Build](https://github.com/mvenditto/SnmpDotNet/actions/workflows/dotnet.yml/badge.svg)](https://github.com/mvenditto/SnmpDotNet/actions/workflows/dotnet.yml) [![codecov](https://codecov.io/gh/mvenditto/SnmpDotNet/branch/master/graph/badge.svg?token=P3JJTXWQ2V)](https://codecov.io/gh/mvenditto/SnmpDotNet)

SnmpDotNet is a NET 6 SNMP client built ontop of `System.Formats.Asn1` BER serialization capabilities.

> :information_source: The library is in early development stage and subject to frequent api changes!

### Goals:
  - support for SNMP V1, V2c and V3
  - modern C# implementation with a focus on memory efficiency
  - low level api + higher-level abstractions to ease usage in common use cases

### A Sneak peek of the Dispatcher API
```csharp
using DotNetSnmp.Client;
using DotNetSnmp.Common.Definitions;
using DotNetSnmp.Protocol.V1;
using DotNetSnmp.Transport;
using DotNetSnmp.Transport.Targets;
using System.Net;

var targetAddress = new IPEndPoint(
    IPAddress.Parse("127.0.0.1"), 161);

var dispatcher = new SnmpDispatcher();

var response = await dispatcher.SendPdu(
    new BasicUdpTransport(targetAddress),
    new CommunityTarget("public"), // dafaults to v1
    targetAddress,
    new GetRequestPdu()
    {
        VariableBindings = new(
            "1.3.6.1.2.1.1.1.0", // sysDescr
            "1.3.6.1.2.1.1.3.0"  // sysUptime
        )
    }
);

foreach(var varBind in response.VariableBindings)
{
    Console.WriteLine(varBind);
}
```
Output:
```bash
1.3.6.1.2.1.1.1.0 = String: SnmpTestAgentContainer
1.3.6.1.2.1.1.3.0 = Timeticks: (471603) 00:01:18:36.02
```
