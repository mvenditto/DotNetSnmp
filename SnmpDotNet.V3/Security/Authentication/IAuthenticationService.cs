namespace SnmpDotNet.Protocol.V3.Security.Authentication
{
    public interface IAuthenticationService
    {
        public int TruncatedDigestSize { get; }

        public int DigestSize { get; }

        ValueTask AuthenticateOutgoingMsg(
            in ReadOnlySpan<byte> wholeMsg, 
            Span<byte> authParameters);

        ValueTask<bool> AuthenticateIncomingMsg(
            in ReadOnlySpan<byte> wholeMsg,
            in ReadOnlySpan<byte> authParams);
    }
}
