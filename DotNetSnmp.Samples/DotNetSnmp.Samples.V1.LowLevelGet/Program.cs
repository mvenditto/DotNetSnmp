using DotNetSnmp.Asn1;
using DotNetSnmp.Protocol.V1;
using DotNetSnmp.Transport;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;

var message = new SnmpV1Message
{
    Community = "public",
    Pdu = new GetRequestPdu()
    {
        RequestId = 42,
        VariableBindings = new("1.3.6.1.2.1.1.1.0")
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
var response = SnmpV1Message.ReadFrom(
        new AsnReader(data, AsnEncodingRules.BER));

// extract the var bind we requested
var sysDescr = response.Pdu.VariableBindings?.First();

// in this simple example we do not rely an SNMP Dispatcher
// to carry the SNMP validation logics for incoming messages.
// let's check that the requestId matches by ourselves
Debug.Assert(response.Pdu.RequestId == message.Pdu.RequestId);

// finally print the resulting varbind
Console.WriteLine(sysDescr);