using SnmpDotNet.Asn1.Serialization;
using System.Formats.Asn1;

namespace SnmpDotNet.Asn1.SyntaxObjects
{
    public readonly record struct Counter64(ulong Value) : IAsnSerializable
    {
        public void WriteTo(AsnWriter writer)
        {
            writer.WriteIntegerUnsigned(
                BitConverter.GetBytes(Value),
                tag: SmiAsnTags.Counter64);
        }

        public void Deconstruct(out ulong value)
        {
            value = Value;
        }

        public static implicit operator ulong(Counter64 x) => x.Value;
    }
}
