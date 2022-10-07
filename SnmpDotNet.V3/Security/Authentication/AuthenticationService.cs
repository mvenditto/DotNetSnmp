using System.Buffers;
using System.Security.Cryptography;

namespace SnmpDotNet.Protocol.V3.Security.Authentication
{
    public class AuthenticationService: IAuthenticationService
    {
        public int TruncatedDigestSize { get; }

        public int DigestSize { get; }

        private readonly HMAC _hmac;

        public AuthenticationService(AuthenticationProtocol authProto, byte[] authkey)
        {
            switch(authProto)
            {
                case AuthenticationProtocol.Md5:
                    _hmac = new HMACMD5(authkey);
                    DigestSize = 16;
                    TruncatedDigestSize = 12;
                    break;
                case AuthenticationProtocol.Sha1:
                    _hmac = new HMACSHA1(authkey);
                    DigestSize = 20;
                    TruncatedDigestSize = 12;
                    break;
                case AuthenticationProtocol.Sha256:
                    _hmac = new HMACSHA256(authkey);
                    DigestSize = 32;
                    TruncatedDigestSize = 24;
                    break;
                case AuthenticationProtocol.Sha384:
                    _hmac = new HMACSHA384(authkey);
                    DigestSize = 48;
                    TruncatedDigestSize = 32;
                    break;
                case AuthenticationProtocol.Sha512:
                    _hmac = new HMACSHA512(authkey);
                    DigestSize = 64;
                    TruncatedDigestSize = 48;
                    break;
                default:
                    throw new ArgumentException();
            };
        }

        public ValueTask AuthenticateOutgoingMsg(
            in ReadOnlySpan<byte> wholeMsg, 
            Span<byte> authParameters)
        {
            var buff = ArrayPool<byte>.Shared.Rent(DigestSize);
            var digest = (Span<byte>) buff;

            if (_hmac.TryComputeHash(wholeMsg, digest, out _))
            {
                digest[..TruncatedDigestSize].CopyTo(authParameters);
            }
            
            ArrayPool<byte>.Shared.Return(buff);

            return ValueTask.CompletedTask;
        }

        public ValueTask<bool> AuthenticateIncomingMsg(
            in ReadOnlySpan<byte> wholeMsg,
            in ReadOnlySpan<byte> authParams)
        {
            Span<byte> digest = stackalloc byte[DigestSize];

            var authenticated = false;

            if (_hmac.TryComputeHash(wholeMsg, digest, out _))
            {
                authenticated = digest[..TruncatedDigestSize].SequenceEqual(authParams);
            }

            return ValueTask.FromResult(authenticated);
        }
    }
}
