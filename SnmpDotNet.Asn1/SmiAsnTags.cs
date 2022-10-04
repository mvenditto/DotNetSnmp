using System.Formats.Asn1;

namespace SnmpDotNet.Asn1.Serialization
{
    public static class SmiAsnTags
    {
        public readonly static Asn1Tag IpAddress = new(TagClass.Application, 0);

        public readonly static Asn1Tag Counter32 = new(TagClass.Application, 1);

        public readonly static Asn1Tag Gauge32 = new(TagClass.Application, 2);

        public readonly static Asn1Tag Unsigned32 = Gauge32;

        public readonly static Asn1Tag TimeTicks = new(TagClass.Application, 3);

        public readonly static Asn1Tag Opaque = new(TagClass.Application, 4);

        public readonly static Asn1Tag Counter64 = new(TagClass.Application, 6);

        public readonly static Asn1Tag Integer32 = Asn1Tag.Integer;
    }
}
