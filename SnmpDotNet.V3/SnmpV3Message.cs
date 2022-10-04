using SnmpDotNet.Asn1.Serialization;
using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Protocol.V3.Security;
using System.Formats.Asn1;

namespace SnmpDotNet.Protocol.V3
{
    public class SnmpV3Message : SnmpMessage
    {
        public override ProtocolVersion ProtocolVersion => ProtocolVersion.SnmpV3;

        public HeaderData GlobalData { get; set; }

        public UsmSecurityParameters SecurityParameters {get; set;}

        public ScopedPdu ScopedPdu { get; set; }

        public override void WriteTo(AsnWriter writer)
        {
            using (_ = writer.PushSequence())
            {
                // versiom
                writer.WriteInteger((int)ProtocolVersion.SnmpV3);

                GlobalData.WriteTo(writer);

                SecurityParameters.WriteTo(writer);

                ScopedPdu.WriteTo(writer);
            }
        }

        public static SnmpV3Message ReadFrom(AsnReader reader)
        {
            // Message ::= SEQUENCE
            var rootSeq = reader.ReadSequence(expectedTag: Asn1Tag.Sequence);

            // version INTEGER
            if (rootSeq.TryReadInt32(out int messageVersion) == false)
            {
                throw new SnmpDecodeException(
                    "Cannot read 'version' number");
            }

            var version = (ProtocolVersion)messageVersion;

            if (version != ProtocolVersion.SnmpV3)
            {
                throw new ArgumentNullException(
                    $"expected version: 3 found: {version}");
            }

            var globalData = HeaderData.ReadFrom(rootSeq);

            var usmSecurityParams = UsmSecurityParameters.ReadFrom(rootSeq);

            var scopedPdu = ScopedPdu.ReadFrom(rootSeq);

            return new()
            {
                GlobalData = globalData,
                SecurityParameters = usmSecurityParams,
                ScopedPdu = scopedPdu
            };
        }
    }
}
