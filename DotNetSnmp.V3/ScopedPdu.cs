using DotNetSnmp.Asn1.Serialization;
using DotNetSnmp.Asn1.SyntaxObjects;
using DotNetSnmp.Common.Definitions;
using DotNetSnmp.Protocol.V1;
using System.Formats.Asn1;
using System.Text;

namespace DotNetSnmp.Protocol.V3
{
    /// <summary>
    /// A scopedPDU is a block of data containing a ContextEngineId, a
    /// ContextName, and a Pdu.
    /// </summary>
    public class ScopedPdu : Pdu
    {
        public Memory<byte> ContextEngineId { get; set; }

        public string ContextName { get; set; }

        public Pdu Pdu { get; set; }

        public override Asn1Tag PduType => Pdu.PduType;

        public new int RequestId => Pdu.RequestId;

        public new PduErrorStatus ErrorStatus => Pdu.ErrorStatus;

        public new int ErrorIndex => Pdu.ErrorIndex;

        public new VarBindList VariableBindings => Pdu.VariableBindings;

        public new bool HasData => Pdu.VariableBindings?.IsEmpty == false;

        public override object Clone()
        {
            return new ScopedPdu
            {
                ContextEngineId = ContextEngineId,
                ContextName = ContextName,
                Pdu = (Pdu) Pdu.Clone()
            };
        }

        public override void WriteTo(AsnWriter writer)
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
