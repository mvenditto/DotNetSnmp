using DotNetSnmp.Asn1.Serialization;
using DotNetSnmp.Asn1.SyntaxObjects;
using DotNetSnmp.Common.Definitions;
using DotNetSnmp.Protocol.V1;
using System.Formats.Asn1;

namespace DotNetSnmp.Protocol.V2
{
    public class BulkRequestPdu: Pdu
    {
        /// <summary>
        /// how many OIDs in the request should be treated as GET request variables
        /// </summary>
        public int NonRepeaters { get; set; } = 0;

        /// <summary>
        /// how many GET_NEXT operations to perform on each variable
        /// </summary>
        public int MaxRepetitions { get; set; } = 0;

        public override Asn1Tag PduType => SnmpAsnTags.BulkMsg;

        public override void WriteTo(AsnWriter writer)
        {
            using (_ = writer.PushSequence(tag: SnmpAsnTags.BulkMsg))
            {
                writer.WriteInteger(RequestId);
                writer.WriteInteger(NonRepeaters);
                writer.WriteInteger(MaxRepetitions);

                if (VariableBindings != null)
                {
                    VariableBindings.WriteTo(writer);
                }
            }
        }

        public override object Clone()
        {
            var cloned = new BulkRequestPdu();
            base.CopyTo(cloned);
            return cloned;
        }
    }
}
