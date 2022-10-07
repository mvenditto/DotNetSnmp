using SnmpDotNet.Asn1.Serialization;
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

        public static SnmpV1Message ReadFrom(AsnReader reader)
        {
            var rootSeq = reader.ReadSequence();

            rootSeq.TryReadInt32(out var version);

            if (version != 0)
            {
                throw new SnmpDecodeException(
                    $"Expected version V1(0) found {version}");
            }

            var community = rootSeq.ReadOctetString();

            var pduType = rootSeq.PeekTag();

            Pdu pdu = null;

            if (pduType == SnmpAsnTags.GetResponseMsg)
            {
                pdu = GetResponsePdu.ReadFrom(rootSeq);
            }
            else if (pduType == SnmpAsnTags.GetMsg)
            {
                pdu = GetRequestPdu.ReadFrom(rootSeq);
            }
            else if (pduType == SnmpAsnTags.GetNextMsg)
            {
                pdu = GetNextRequestPdu.ReadFrom(rootSeq);
            }

            return new SnmpV1Message
            {
                Community = Encoding.UTF8.GetString(community),
                Pdu = pdu!
            };
        }
    }
}
