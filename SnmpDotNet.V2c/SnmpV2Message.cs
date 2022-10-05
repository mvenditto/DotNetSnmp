using SnmpDotNet.Asn1.Serialization;
using SnmpDotNet.Common.Definitions;
using System.Formats.Asn1;
using System.Text;

namespace SnmpDotNet.Protocol.V1
{
    public class SnmpV2Message: SnmpV1Message
    {
        public override ProtocolVersion ProtocolVersion => ProtocolVersion.SnmpV2c;

        public override void WriteTo(AsnWriter writer)
        {
            using (_ = writer.PushSequence())
            {
                // versiom
                writer.WriteInteger((int) ProtocolVersion.SnmpV2c);

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

            if (version != 1)
            {
                throw new SnmpDecodeException(
                    $"Expected version V2c(1) found {version}");
            }

            var community = rootSeq.ReadOctetString();

            var pduType = rootSeq.PeekTag();

            Pdu pdu = null;

            if (pduType == SnmpAsnTags.GetResponseMsg)
            {
                pdu = GetResponsePdu.ReadFrom(rootSeq);
            }
            else if (pduType == SnmpAsnTags.BulkMsg)
            {
                throw new NotImplementedException();
            }
            else if (pduType == SnmpAsnTags.InformMsg)
            {
                throw new NotImplementedException();
            }
            else if (pduType == SnmpAsnTags.GetMsg)
            {
                pdu = GetRequestPdu.ReadFrom(rootSeq);
            }

            return new SnmpV2Message
            {
                Community = Encoding.UTF8.GetString(community),
                Pdu = pdu!
            };
        }
    }
}
