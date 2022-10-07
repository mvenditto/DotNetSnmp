# SnmpDotNet
[![Build](https://github.com/mvenditto/SnmpDotNet/actions/workflows/dotnet.yml/badge.svg)](https://github.com/mvenditto/SnmpDotNet/actions/workflows/dotnet.yml) [![codecov](https://codecov.io/gh/mvenditto/SnmpDotNet/branch/master/graph/badge.svg?token=P3JJTXWQ2V)](https://codecov.io/gh/mvenditto/SnmpDotNet)

SnmpDotNet is a NET 6 SNMP client built ontop of `System.Formats.Asn1` BER serialization capabilities.

> :information_source: The library is in early development stage and subject to frequent api changes! <br>
> (At the moment it is actually the product of a weekend-project, so be nice :)

### Goals:
  - support for SNMP V1, V2c and V3
  - modern C# implementation with a focus on memory efficiency
  - low level api + higher-level abstractions to ease usage in common use cases

### A Sneak peek of the most basic "low-level" api usage
```csharp
using SnmpDotNet.Client;
using SnmpDotNet.Protocol.V1;
using static System.Net.IPAddress;

var get = new SnmpV1Message
{
    Community = "public",
    Pdu = new GetRequestPdu
    {
        VariableBindings = new(
            "1.3.6.1.2.1.1.1.0", // sysDescr
            "1.3.6.1.2.1.1.3.0"  // sysUptime
        )
    }
};

using var client = new SnmpUdpClient(new (Loopback, 161));

var res = await client.GetAsync(get);

foreach (var(name, value) in res.VariableBindings)
{
    Console.WriteLine($"{name}: {value}");
}
```
Output:
```bash
1.3.6.1.2.1.1.1.0: String: SnmpDotNet will be cool :)
1.3.6.1.2.1.1.3.0: TimeTicks: (49956) 0:08:19.56
```
