using DotNetSnmp.Asn1;
using DotNetSnmp.Asn1.Serialization;
using DotNetSnmp.Asn1.SyntaxObjects;
using DotNetSnmp.Protocol.V1;
using DotNetSnmp.Samples.V1.LowLevelTableTraversal;
using DotNetSnmp.Transport;
using System.Data;
using System.Formats.Asn1;
using System.Net;

const string sysOrTable = "1.3.6.1.2.1.1.9";

var target = new IPEndPoint(
    IPAddress.Parse("127.0.0.1"), 161);

var transport = new BasicUdpTransport(target);

var endOfTableReached = false;
var nextOid = sysOrTable;
var values = new List<IAsnSerializable>();

while (endOfTableReached == false)
{
    var message = new SnmpV1Message
    {
        Community = "public",

        Pdu = new GetNextRequestPdu()
        {
            RequestId = 42,
            VariableBindings = new(nextOid)
        }
    };

    var packet = message.Encode();

    _ = await transport.SendAsync(packet, target);

    var data = await transport.ReceiveAsync(target);

    var response = SnmpV1Message.ReadFrom(
        new AsnReader(data, AsnEncodingRules.BER));

    var varBind = response.Pdu.VariableBindings!.First();

    nextOid = varBind.Name;

    if (!nextOid.StartsWith(sysOrTable))
    {
        endOfTableReached = true;
    }
    else
    {
        values.Add(varBind.Value);
    }
}


using var dt = new DataTable();
dt.Columns.Add("sysOrOID", typeof(string));
dt.Columns.Add("sysOrDescr", typeof(string));
dt.Columns.Add("sysOrUptime", typeof(TimeTicks));

var numRows = values.Count / dt.Columns.Count;

var columns = values
    .Chunk(numRows)
    .Select(x => x.ToList())
    .ToList();

for (var i = 0; i < numRows; i++)
{
    var row = dt.NewRow();
    row[0] = columns[0][i];
    row[1] = columns[1][i];
    row[2] = columns[2][i];
    dt.Rows.Add(row);
}

dt.PrettyPrint();