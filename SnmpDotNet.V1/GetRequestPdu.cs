using SnmpDotNet.Asn1.Serialization;
using SnmpDotNet.Asn1.SyntaxObjects;
using SnmpDotNet.Common.Definitions;
using System.Formats.Asn1;

namespace SnmpDotNet.Protocol.V1
{
    public class GetRequestPdu: Pdu
    {
        public override Asn1Tag PduType => SnmpAsnTags.GetMsg;

        public GetRequestPdu()
        {
            ErrorIndex = 0;
            ErrorStatus = PduErrorStatus.NoError;
        }

        public override void WriteTo(AsnWriter writer)
        {
            using (_ = writer.PushSequence(tag: PduType))
            {
                writer.WriteInteger(RequestId);
                writer.WriteInteger((int) ErrorStatus);
                writer.WriteInteger(ErrorIndex);
                if (VariableBindings != null)
                {
                    VariableBindings.WriteTo(writer);
                }
            }
        }

        public static GetRequestPdu ReadFrom(AsnReader reader)
        {
            var seq = reader.ReadSequence(
                expectedTag: SnmpAsnTags.GetMsg);

            seq.TryReadInt32(out var requestId);
            seq.TryReadInt32(out var errorStatus);
            seq.TryReadInt32(out var errorIndex);

            var bindings = VarBindList.ReadFrom(seq);

            return new GetRequestPdu
            {
                RequestId = requestId,
                ErrorStatus = (PduErrorStatus) errorStatus,
                ErrorIndex = errorIndex,
                VariableBindings = bindings
            };
        }

        public override object Clone()
        {
            var cloned = new GetRequestPdu();
            base.CopyTo(cloned);
            return cloned;
        }
    }
}
