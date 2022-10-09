using SnmpDotNet.Asn1.Serialization;
using System.Formats.Asn1;

namespace SnmpDotNet.Asn1.SyntaxObjects
{
    public readonly record struct OpaqueInteger64(long Value) : IAsnSerializable
    {
        public void Deconstruct(out long value)
        {
            value = Value;
        }

        public void WriteTo(AsnWriter writer)
        {
            var writer2 = new AsnWriter(AsnEncodingRules.BER);

            writer2.WriteInteger(Value,
                tag: AsnTypes.OpaqueInteger64);

            writer.WriteOctetString(
                writer2.Encode(),
                AsnTypes.Opaque);
        }

        public static OpaqueInteger64 ReadFrom(AsnReader reader)
        {
            var opaque = reader.ReadOctetString(AsnTypes.Opaque);

            if (opaque.Length > 2)
            {
                if (opaque[0] == AsnTypes.AsnOpaqueTag1)
                {
                    var opaqueR = new AsnReader(opaque, AsnEncodingRules.BER);

                    byte type = opaque[1];

                    if (type == AsnTypes.OpaqueInteger64.TagValue)
                    {
                        opaqueR.TryReadInt64(out var integer64, AsnTypes.OpaqueInteger64);
                        return new(integer64);
                    }
                }
            }

            throw new ArgumentException(
                "Cannot deserialize an Opaque{Integer64} from the reader");
        }
    }
}
