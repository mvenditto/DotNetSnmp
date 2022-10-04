using SnmpDotNet.Asn1.Serialization;
using SnmpDotNet.Asn1.SyntaxObjects;
using System.Formats.Asn1;

namespace SnmpDotNet.Common.Definitions
{
    public abstract class Pdu : IAsnSerializable
    {
        public abstract Asn1Tag PduType { get; }

        public int RequestId { get; set; } = 0;

        public PduErrorStatus ErrorStatus { get; set; } = 0;

        public int ErrorIndex { get; set; } = 0;

        public VarBindList? VariableBindings { get; set; }

        public abstract void WriteTo(AsnWriter writer);
    }
}
