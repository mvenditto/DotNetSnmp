using DotNetSnmp.Asn1;
using DotNetSnmp.Protocol.V2;
using DotNetSnmp.Transport;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;

var message = new SnmpV2Message
{
    Community = "public",
    Pdu = new BulkRequestPdu()
    {
        NonRepeaters = 1,
        MaxRepetitions = 2,
        RequestId = 42,
        VariableBindings = new(
            "1.3.6.1.2.1.1.3.0",     // sysUptime.0
            "1.3.6.1.2.1.4.22.1.2",  // ipNetToMediaPhysAddress 
            "1.3.6.1.2.1.4.22.1.4"   // ipNetToMediaEntry 
        )
    }
};

// BER encode the packet
var packet = message.Encode();

/*
define a target, aka remote agent.
in this sample the agent is running
on localhost as the client does
so we reuse the same IPEndPoint for booth
*/
var target = new IPEndPoint(
    IPAddress.Parse("127.0.0.1"), 161);

// define a default UDP transport
var transport = new BasicUdpTransport(target);

// send the message to 127.0.0.1:161
_ = await transport.SendAsync(packet, target);

// receive the response from 127.0.0.1:161
var data = await transport.ReceiveAsync(target);

// decode the response message
var response = SnmpV2Message.ReadFrom(
        new AsnReader(data, AsnEncodingRules.BER));

Debug.Assert(response.Pdu.RequestId == message.Pdu.RequestId);

foreach (var (oid, value) in response.Pdu.VariableBindings!)
{
    Console.WriteLine($"{oid} = {value}");
}