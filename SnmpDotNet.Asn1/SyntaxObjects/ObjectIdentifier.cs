using SnmpDotNet.Asn1.Serialization;
using System.Formats.Asn1;

namespace SnmpDotNet.Asn1.SyntaxObjects
{
    public readonly record struct ObjectIdentifier(string Oid) : IAsnSerializable
    {
        public void WriteTo(AsnWriter writer)
        {
            writer.WriteObjectIdentifier(Oid);
        }

        public override string ToString() => Oid;

        public static implicit operator string(ObjectIdentifier o) => o.Oid;
    }
}
