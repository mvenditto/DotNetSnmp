using SnmpDotNet.Asn1;
using SnmpDotNet.Protocol.V1;
using SnmpDotNet.Transport;
using System.Data;
using System.Formats.Asn1;
using System.Net;

const string ifTable = "1.3.6.1.2.1.2.2";

var target = new IPEndPoint(
    IPAddress.Parse("127.0.0.1"), 161);

var transport = new BasicUdpTransport(target);

var ifTableColumns = new string[]
{
    "ifIndex",
    "ifDescr",
    "ifType",
    "ifMtu",
    "ifSpeed",
    "ifPhysAddress",
    "ifAdminStatus",
    "ifOperStatus",
    "ifLastChange",
    "ifInOctets",
    "ifInUcastPkts",
    "ifInNUcastPkts",
    "ifInDiscards",
    "ifInErrors",
    "ifInUnknownProtos",
    "ifOutOctets",
    "ifOutUcastPkts",
    "ifOutNUcastPkts",
    "ifOutDiscards",
    "ifOutErrors",
    "ifOutQLen",
    "ifSpecific"
};

var endOfTableReached = false;

var nextOid = ifTable;

using var dt = new DataTable();

foreach (var colName in ifTableColumns)
{
    dt.Columns.Add(colName);
}


var columnIdx = 0;
var currRow = dt.NewRow();

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

    if (!nextOid.StartsWith(ifTable))
    {
        endOfTableReached = true;
    }
    else
    {
        Console.WriteLine(varBind);
        
        currRow[columnIdx] = varBind.Value;

        columnIdx += 1;

        if (columnIdx >= ifTableColumns.Length)
        {
            columnIdx = 0;
            dt.Rows.Add(currRow);
            currRow = dt.NewRow();
        }
    }
}

Console.WriteLine(dt);