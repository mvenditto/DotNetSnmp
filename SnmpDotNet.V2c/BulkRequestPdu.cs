using SnmpDotNet.Asn1.Serialization;
using SnmpDotNet.Asn1.SyntaxObjects;
using System.Formats.Asn1;

namespace SnmpDotNet.Protocol.V2
{
    internal class BulkRequestPdu: IAsnSerializable
    {
        public int RequestId { get; set; } = 0;

        public int NonRepeaters { get; set; } = 0;

        public int MaxRepetitions { get; set; } = 0;

        public VarBindList? VariableBindings { get; set; }

        public void WriteTo(AsnWriter writer)
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
    }
}
