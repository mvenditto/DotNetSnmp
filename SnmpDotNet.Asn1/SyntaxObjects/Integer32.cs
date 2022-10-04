using SnmpDotNet.Asn1.Serialization;
using System.Formats.Asn1;

namespace SnmpDotNet.Asn1.SyntaxObjects
{
    public readonly record struct Integer32(int Value) : IAsnSerializable
    {
        public void WriteTo(AsnWriter writer)
        {
            writer.WriteIntegerUnsigned(
                BitConverter.GetBytes(Value),
                tag: SmiAsnTags.Integer32);
        }

        public void Deconstruct(out int value)
        {
            value = Value;
        }

        public static implicit operator int(Integer32 x) => x.Value;
    }
}
