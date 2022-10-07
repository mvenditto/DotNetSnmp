using SnmpDotNet.Asn1.Serialization;
using SnmpDotNet.Asn1.SyntaxObjects;
using SnmpDotNet.Common.Definitions;
using System.Formats.Asn1;

namespace SnmpDotNet.Protocol.V1
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
    }
}
