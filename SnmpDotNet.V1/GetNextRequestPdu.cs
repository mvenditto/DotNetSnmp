using SnmpDotNet.Asn1.Serialization;
using System.Formats.Asn1;

namespace SnmpDotNet.Protocol.V1
{
    public class GetNextRequestPdu: GetRequestPdu
    {
        public override Asn1Tag PduType => SnmpAsnTags.GetNextMsg;
    }
}
