using DotNetSnmp.Asn1.Serialization;
using DotNetSnmp.Asn1.SyntaxObjects;
using DotNetSnmp.Common.Definitions;
using System.Formats.Asn1;

namespace DotNetSnmp.Protocol.V1
{
    public class ReportPdu : Pdu
    {
        public override Asn1Tag PduType => SnmpAsnTags.ReportMsg;

        public override void WriteTo(AsnWriter writer)
        {
            throw new NotImplementedException();
        }

        public static GetResponsePdu ReadFrom(AsnReader reader)
        {
            var seq = reader.ReadSequence(
                expectedTag: SnmpAsnTags.ReportMsg);

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
            var cloned = new ReportPdu();
            base.CopyTo(cloned);
            return cloned;
        }
    }
}
