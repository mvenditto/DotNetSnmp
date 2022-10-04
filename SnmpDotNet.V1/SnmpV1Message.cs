using SnmpDotNet.Common.Definitions;
using System.Formats.Asn1;
using System.Text;

namespace SnmpDotNet.Protocol.V1
{
    public class SnmpV1Message: SnmpMessage
    {
        public override ProtocolVersion ProtocolVersion => ProtocolVersion.SnmpV1;

        public string Community { get; set; }

        public Pdu Pdu { get; set; }

        public override void WriteTo(AsnWriter writer)
        {
            using (_ = writer.PushSequence())
            {
                // versiom
                writer.WriteInteger((int) ProtocolVersion.SnmpV1);

                // community
                writer.WriteOctetString(
                    Encoding.UTF8.GetBytes(Community));

                // pdu
                Pdu?.WriteTo(writer);
            }
        }
    }
}
