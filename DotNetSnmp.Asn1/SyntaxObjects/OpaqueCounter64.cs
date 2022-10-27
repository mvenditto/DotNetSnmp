using DotNetSnmp.Asn1.Serialization;
using System.Formats.Asn1;

namespace DotNetSnmp.Asn1.SyntaxObjects
{
    public readonly record struct OpaqueCounter64(ulong Value) : IAsnSerializable
    {
        public void Deconstruct(out ulong value)
        {
            value = Value;
        }

        public void WriteTo(AsnWriter writer)
        {
            var writer2 = new AsnWriter(AsnEncodingRules.BER);

            writer2.WriteInteger(Value,
                tag: AsnTypes.OpaqueCounter64);

            writer.WriteOctetString(
                writer2.Encode(), 
                AsnTypes.Opaque);
        }

        public static OpaqueCounter64 ReadFrom(AsnReader reader)
        {
            var opaque = reader.ReadOctetString(AsnTypes.Opaque);

            if (opaque.Length > 2)
            {
                if (opaque[0] == AsnTypes.AsnOpaqueTag1)
                {
                    var opaqueR = new AsnReader(opaque, AsnEncodingRules.BER);

                    byte type = opaque[1];

                    if (type == AsnTypes.OpaqueCounter64.TagValue)
                    {
                        opaqueR.TryReadUInt64(out var counter64, AsnTypes.OpaqueCounter64);
                        return new(counter64);
                    }
                }
            }

            throw new ArgumentException(
                "Cannot deserialize an Opaque{Counter64} from the reader");
        }
    }
}
