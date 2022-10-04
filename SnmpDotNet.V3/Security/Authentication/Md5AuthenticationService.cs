using System.Security.Cryptography;

namespace SnmpDotNet.Protocol.V3.Security.Authentication
{
    public class Md5AuthenticationService : IAuthenticationService
    {
        public int TruncatedDigestSize => 12;

        public int DigestSize => 16;

        public ValueTask<int> AuthenticateIncomingMsg(
            in ReadOnlySpan<byte> authKey, 
            in ReadOnlySpan<byte> authParams, 
            in ReadOnlySpan<byte> wholeMsg, 
            Span<byte> authenticatedWholeMsgDestination)
        {
            throw new NotImplementedException();
        }

        public ValueTask AuthenticateOutgoingMsg(
            in ReadOnlySpan<byte> authKey, 
            in ReadOnlySpan<byte> wholeMsg, 
            Span<byte> authParameters)
        {
            var digest = HMACMD5.HashData(authKey, wholeMsg);
            digest[..TruncatedDigestSize].CopyTo(authParameters);
            return ValueTask.CompletedTask;
        }
    }
}
