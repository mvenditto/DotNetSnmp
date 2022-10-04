using SnmpDotNet.Asn1.Serialization;
using SnmpDotNet.Protocol.V3.Security.Authentication;
using SnmpDotNet.Protocol.V3.Security.Privacy;
using System.Formats.Asn1;
using System.Text;

namespace SnmpDotNet.Protocol.V3.Security
{
    public class UsmSecurityParameters : IAsnSerializable
    {
        public Memory<byte> AuthoritativeEngineId { get; set; }

        public int AuthoritativeEngineBoots { get; set; }

        public int AuthoritativeEngineTime { get; set; }

        public string UserName { get; set; }

        public IAuthenticationService? AuthenticationService { get; set; }

        public IPrivacyService? PrivacyService { get; set; }

        public Memory<byte> AuthParams { get; set; } = Memory<byte>.Empty;

        public Memory<byte> PrivParams { get; set; } = Memory<byte>.Empty;

        public void WriteTo(AsnWriter writer)
        {
            var innerSeq = new AsnWriter(AsnEncodingRules.BER);

            using (_ = innerSeq.PushSequence())
            {
                innerSeq.WriteOctetString(AuthoritativeEngineId.Span);

                innerSeq.WriteInteger(AuthoritativeEngineBoots);

                innerSeq.WriteInteger(AuthoritativeEngineTime);

                innerSeq.WriteOctetString(
                    Encoding.UTF8.GetBytes(UserName));
                
                if (AuthenticationService != null)
                {
                    if (AuthParams.IsEmpty)
                    {
                        AuthParams = new byte[AuthenticationService.TruncatedDigestSize];
                    }
                    
                    innerSeq.WriteOctetString(AuthParams.Span);
                }   
                else
                {
                    innerSeq.WriteOctetString(Span<byte>.Empty);
                }

                if (PrivacyService != null)
                {
                    if (PrivParams.IsEmpty)
                    {
                        PrivParams = new byte[PrivacyService.PrivacyParametersLength];
                    }
                    innerSeq.WriteOctetString(PrivParams.Span);
                }
                else
                {
                    innerSeq.WriteOctetString(Span<byte>.Empty);
                }
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
                AuthoritativeEngineId = engineId,
                AuthoritativeEngineBoots = engineBoots,
                AuthoritativeEngineTime = engineTime,
                UserName = Encoding.UTF8.GetString(userName),
                AuthParams = authParams,
                PrivParams = privParams
            };
        }
    }
}
