using SnmpDotNet.Asn1.Serialization;
using System.Formats.Asn1;

namespace SnmpDotNet.Asn1.SyntaxObjects
{
    public readonly record struct Null : IAsnSerializable
    {
        public readonly static Null Instance = new();

        public void WriteTo(AsnWriter writer)
        {
            writer.WriteNull();
        }

        public override string ToString()
        {
            return "NULL";
        }
    }
}
