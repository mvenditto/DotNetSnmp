using SnmpDotNet.Asn1.Serialization;
using SnmpDotNet.Protocol.V3.Security.Authentication;
using SnmpDotNet.V3.Security.Privacy;
using System.Formats.Asn1;
using System.Text;

namespace SnmpDotNet.Protocol.V3.Security
{
    public class UsmSecurityParameters : IAsnSerializable
    {
        public Memory<byte> EngineId { get; set; }

        public int EngineBoots { get; set; }

        public int EngineTime { get; set; }

        public string SecurityName { get; set; }

        public AuthenticationProtocol AuthenticationProtocol { get; set; } 
            = AuthenticationProtocol.None;

        public PrivacyProtocol PrivacyProtocol { get; set; }
            = PrivacyProtocol.None;

        public Memory<byte> AuthParams { get; set; } = Memory<byte>.Empty;

        public Memory<byte> PrivParams { get; set; } = Memory<byte>.Empty;

        public void WriteTo(AsnWriter writer)
        {
            var innerSeq = new AsnWriter(AsnEncodingRules.BER);

            using (_ = innerSeq.PushSequence())
            {
                innerSeq.WriteOctetString(EngineId.Span);

                innerSeq.WriteInteger(EngineBoots);

                innerSeq.WriteInteger(EngineTime);

                innerSeq.WriteOctetString(
                    Encoding.UTF8.GetBytes(SecurityName));
                
                if (AuthenticationProtocol != AuthenticationProtocol.None)
                {
                    if (AuthParams.IsEmpty)
                    {
                        var authParamsSize = AuthenticationProtocol.TruncatedDigestSize();
                        AuthParams = new byte[authParamsSize];
                    }
                }

                innerSeq.WriteOctetString(AuthParams.Span);

                if (PrivacyProtocol != PrivacyProtocol.None)
                {
                    if (PrivParams.IsEmpty)
                    {
                        // PrivParams = new byte[0]; // TODO
                    }
                }
                innerSeq.WriteOctetString(PrivParams.Span);
            }

            var innerSequence = innerSeq.Encode();

            writer.WriteOctetString(innerSequence);
        }

        public static UsmSecurityParameters ReadFrom(AsnReader reader)
        {
            var innerSeqBytes = reader.ReadOctetString();

            var innerSeqReader = new AsnReader(innerSeqBytes, AsnEncodingRules.BER);

            var innerSeq = innerSeqReader.ReadSequence();

            var engineId = innerSeq.ReadOctetString();

            innerSeq.TryReadInt32(out var engineBoots);

            innerSeq.TryReadInt32(out var engineTime);

            var userName = innerSeq.ReadOctetString();

            var authParams = innerSeq.ReadOctetString();

            var privParams = innerSeq.ReadOctetString();

            return new()
            {
                EngineId = engineId,
                EngineBoots = engineBoots,
                EngineTime = engineTime,
                SecurityName = Encoding.UTF8.GetString(userName),
                AuthParams = authParams,
                PrivParams = privParams
            };
        }
    }
}
