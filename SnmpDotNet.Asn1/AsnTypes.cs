using System.Formats.Asn1;

namespace SnmpDotNet.Asn1.Serialization
{
    public static class AsnTypes
    {
        public readonly static Asn1Tag IpAddress = new(TagClass.Application, 0);

        public readonly static Asn1Tag Counter32 = new(TagClass.Application, 1);

        public readonly static Asn1Tag Gauge32 = new(TagClass.Application, 2);

        public readonly static Asn1Tag Unsigned32 = Gauge32;

        public readonly static Asn1Tag TimeTicks = new(TagClass.Application, 3);

        public readonly static Asn1Tag Opaque = new(TagClass.Application, 4);

        public readonly static Asn1Tag Counter64 = new(TagClass.Application, 6);

        public readonly static Asn1Tag Integer32 = Asn1Tag.Integer;

        public readonly static Asn1Tag Unsigned64 = Counter64;

        public readonly static Asn1Tag Float = new(TagClass.Application, 8);

        public readonly static Asn1Tag Double = new(TagClass.Application, 9);

        #region draft-perkins-opaque-01.txt Opaque types
        public const byte AsnContext = (byte) TagClass.ContextSpecific; //0x80, 128

        public const byte AsnExtensionId = 0x1F; // 31

        /// <summary>
        /// First octet of the tag
        /// </summary>
        public const byte AsnOpaqueTag1 = AsnContext | AsnExtensionId; // 159

        /// <summary>
        /// Base value for the second octet of the tag
        /// the second octet is the value for the tag
        /// </summary>
        public const byte AsnOpaqueTag2 = 0x30; // 48

        /// <summary>
        /// Second octet of tag for unions
        /// </summary>
        public const byte AsnOpaqueTag2U = 0x2f; // 47

        // 0x40
        private const byte Application = (byte) TagClass.Application;
        private const byte _counter64 = 6;
        private const byte _float = 8;
        private const byte _double = 9;

        public const int AsnOpaqueCounter64TagValue // 48 + (64 | 6) = 118
            = AsnOpaqueTag2 + (Application | _counter64);

        public const int AsnOpaqueFloatTagValue     // 48 + (64 | 6) = 120
            = AsnOpaqueTag2 + (Application | _float);

        public const int AsnOpaqueDoubleTagValue    // 48 + (64 | 6) = 121
            = AsnOpaqueTag2 + (Application | _double);

        public readonly static Asn1Tag OpaqueCounter64 = 
            new(TagClass.ContextSpecific, AsnOpaqueCounter64TagValue);

        public readonly static Asn1Tag OpaqueFloat = 
            new(TagClass.ContextSpecific, AsnOpaqueFloatTagValue);

        public readonly static Asn1Tag OpaqueDouble = 
            new(TagClass.ContextSpecific, AsnOpaqueDoubleTagValue);
        #endregion
    }
}
