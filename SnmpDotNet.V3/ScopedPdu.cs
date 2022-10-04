using SnmpDotNet.Asn1.Serialization;
using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Protocol.V1;
using System.Formats.Asn1;
using System.Text;

namespace SnmpDotNet.Protocol.V3
{
    public class ScopedPdu : IAsnSerializable
    {
        public Memory<byte> ContextEngineId { get; set; }

        public string ContextName { get; set; }

        public Pdu Pdu { get; set; }

        public void WriteTo(AsnWriter writer)
        {
            using (_ = writer.PushSequence())
            {
                var enc = Encoding.UTF8;

                writer.WriteOctetString(ContextEngineId.Span);

                writer.WriteOctetString(
                    ContextName.GetBytesSpanOrDefault(enc));

                Pdu.WriteTo(writer);
            }
        }

        public static ScopedPdu ReadFrom(AsnReader reader)
        {
            var seq = reader.ReadSequence();

            var ctxEngineId = seq.ReadOctetString();

            var ctxName = seq.ReadOctetString();

            var utf8 = Encoding.UTF8;

            var pduTag = seq.PeekTag();

            Pdu pdu = null;

            if (pduTag == SnmpAsnTags.GetResponseMsg)
            {
                pdu = GetResponsePdu.ReadFrom(seq);
            }
            else if (pduTag == SnmpAsnTags.ReportMsg)
            {
                pdu = ReportPdu.ReadFrom(seq);
            }

            return new()
            {
                ContextEngineId = ctxEngineId,
                ContextName = utf8.GetString(ctxName),
                Pdu = pdu
            };
        }
    }
}
