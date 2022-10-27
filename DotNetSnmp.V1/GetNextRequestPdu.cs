using DotNetSnmp.Asn1.Serialization;
using DotNetSnmp.Asn1.SyntaxObjects;
using DotNetSnmp.Common.Definitions;
using System.Formats.Asn1;

namespace DotNetSnmp.Protocol.V1
{
    public class GetNextRequestPdu: GetRequestPdu
    {
        public override Asn1Tag PduType => SnmpAsnTags.GetNextMsg;

        public static GetNextRequestPdu ReadFrom(AsnReader reader)
        {
            var seq = reader.ReadSequence(
                expectedTag: SnmpAsnTags.GetNextMsg);

            seq.TryReadInt32(out var requestId);
            seq.TryReadInt32(out var errorStatus);
            seq.TryReadInt32(out var errorIndex);

            var bindings = VarBindList.ReadFrom(seq);

            return new GetNextRequestPdu
            {
                RequestId = requestId,
                ErrorStatus = (PduErrorStatus)errorStatus,
                ErrorIndex = errorIndex,
                VariableBindings = bindings
            };
        }
        public override object Clone()
        {
            var cloned = new GetNextRequestPdu();
            base.CopyTo(cloned);
            return cloned;
        }
    }
}
