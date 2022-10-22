using SnmpDotNet.Asn1.Serialization;
using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Protocol.V1;
using System.Formats.Asn1;
using System.Text;

namespace SnmpDotNet.Protocol.V3
{
    /// <summary>
    /// A scopedPDU is a block of data containing a ContextEngineId, a
    /// ContextName, and a Pdu.
    /// </summary>
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

            var pduType = seq.PeekTag();

            Pdu pdu = null;
            if (pduType == SnmpAsnTags.GetResponseMsg)
            {
                pdu = GetResponsePdu.ReadFrom(seq);
            }
            if (pduType == SnmpAsnTags.GetMsg)
            {
                pdu = GetRequestPdu.ReadFrom(seq);
            }
            else if (pduType == SnmpAsnTags.GetNextMsg)
            {
                pdu = GetNextRequestPdu.ReadFrom(seq);
            }
            else if (pduType == SnmpAsnTags.BulkMsg)
            {
                throw new NotImplementedException();
            }
            else if (pduType == SnmpAsnTags.InformMsg)
            {
                throw new NotImplementedException();
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
