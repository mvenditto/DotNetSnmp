using SnmpDotNet.Asn1.Serialization;
using System.Formats.Asn1;

namespace SnmpDotNet.Asn1
{
    public static class AsnSerializableExtensions
    {
        public static byte[] Encode(this IAsnSerializable obj)
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);
            obj.WriteTo(writer);
            return writer.Encode();
        }

        public static int Encode(this IAsnSerializable obj, Span<byte> destination)
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);
            obj.WriteTo(writer);
            return writer.Encode(destination);
        }
    }
}
