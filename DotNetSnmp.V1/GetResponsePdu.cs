using DotNetSnmp.Asn1.Serialization;
using DotNetSnmp.Asn1.SyntaxObjects;
using DotNetSnmp.Common.Definitions;
using System.Formats.Asn1;

namespace DotNetSnmp.Protocol.V1
{
    public class GetResponsePdu : Pdu
    {
        public override Asn1Tag PduType => SnmpAsnTags.GetResponseMsg;

        public override void WriteTo(AsnWriter writer)
        {
            using (_ = writer.PushSequence(tag: SnmpAsnTags.GetResponseMsg))
            {
                writer.WriteInteger(RequestId);
                writer.WriteInteger((int)ErrorStatus);
                writer.WriteInteger(ErrorIndex);
                if (VariableBindings != null)
                {
                    VariableBindings.WriteTo(writer);
                }
            }
        }

        public static GetResponsePdu ReadFrom(AsnReader reader)
        {
            var seq = reader.ReadSequence(
                expectedTag: SnmpAsnTags.GetResponseMsg);

            seq.TryReadInt32(out var requestId);
            seq.TryReadInt32(out var errorStatus);
            seq.TryReadInt32(out var errorIndex);

            var bindings = VarBindList.ReadFrom(seq);

            return new GetResponsePdu
            {
                RequestId = requestId,
                ErrorStatus = (PduErrorStatus) errorStatus,
                ErrorIndex = errorIndex,
                VariableBindings = bindings
            };
        }

        public override object Clone()
        {
            var cloned = new GetResponsePdu();
            base.CopyTo(cloned);
            return cloned;
        }
    }
}
