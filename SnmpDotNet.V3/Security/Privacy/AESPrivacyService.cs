using System.Buffers;
using System.Security.Cryptography;
using SnmpDotNet.Common.Helpers;

namespace SnmpDotNet.Protocol.V3.Security.Privacy
{
    public class AESPrivacyService : IPrivacyService, IDisposable
    {
        public int PrivacyParametersLength => 8;

        private readonly Aes _aes;

        private readonly byte[] _bufferBackArray;

        private readonly byte[] _paddingBuffer;

        private readonly Memory<byte> _privacyKey;

        private readonly Memory<byte> _engineBoots;

        private readonly Memory<byte> _engineTime;

        private long _salt = -1;

        public AESPrivacyService(
            in byte[] privacyKey,
            in int engineBoots,
            in int engineTime)
        {
            if (privacyKey.Length < 16)
            {
                throw new ArgumentException("privKey for AES-CBC must be 16 bytes.");
            }

            _aes = Aes.Create();
            _aes.BlockSize = 128;
            _aes.FeedbackSize = 128;
            _aes.KeySize = privacyKey.Length * 8;
            _aes.Padding = PaddingMode.Zeros;
            _aes.Mode = CipherMode.CFB;

            _paddingBuffer = ArrayPool<byte>.Shared.Rent(65507);

            _bufferBackArray = ArrayPool<byte>.Shared.Rent(24);

            _privacyKey = (Memory<byte>)_bufferBackArray[..16];

            _engineBoots = (Memory<byte>)_bufferBackArray[16..20];

            _engineTime = (Memory<byte>)_bufferBackArray[20..24];

            // cache engineBoots and engineTime beacause a change
            // in these values equates to a 'reboot' or similar of the
            // authoritave snmp engine, a resync is needed
            UpdateEngineBoots(engineBoots);
            UpdateEngineTime(engineTime);

            privacyKey.CopyTo(_privacyKey);

            _aes.Key = _privacyKey[..16].ToArray();
        }

        public void UpdateEngineBoots(int authoritativeEngineBoots)
        {
            BinaryHelpers.CopyBytesMostSignificantFirst(
                authoritativeEngineBoots,
                _engineBoots.Span);
        }

        public void UpdateEngineTime(int authoritativeEngineTime)
        {
            BinaryHelpers.CopyBytesMostSignificantFirst(
                authoritativeEngineTime,
                _engineTime.Span);
        }

        private long GetNextSalt()
        {
            if (_salt < 0)
            {
                _salt = Random.Shared.NextInt64();
                return _salt;
            }

            _salt = (_salt + 1) % long.MaxValue;

            return _salt;
        }

        public int EncryptScopedPdu(
            in ReadOnlyMemory<byte> scopedPdu,
            Span<byte> privParameters,
            Span<byte> encryptedScopedPdu)
        {
            // generate an 8-octet salt value
            ReadOnlySpan<byte> salt = BitConverter.GetBytes((long) 1848320124);//  GetNextSalt());

            Span<byte> iv = stackalloc byte[16];

            // first 4 octets (Most Significant Byte first)
            _engineBoots.Span.CopyTo(iv[..4]);

            // next 4 octets (Most Significant Byte first)
            _engineTime.Span.CopyTo(iv[4..8]);

            BinaryHelpers.CopyBytesMostSignificantFirst(
                (long)1848320124, iv[8..]);

            // copy the 64 bit salt to privParameters
            iv[8..16].CopyTo(privParameters);

            return _aes.EncryptCfb(
                scopedPdu.Span,
                iv,
                encryptedScopedPdu,
                PaddingMode.Zeros);
        }

        public Memory<byte> DecryptScopedPdu(
            ReadOnlyMemory<byte> encryptedPdu,
            ReadOnlyMemory<byte> privParameters)
        {
            ReadOnlySpan<byte> salt = privParameters.Span;

            // rebuild the IV used to encrypt the pdu
            Span<byte> iv = stackalloc byte[16];

            // first 4 octets (Most Significant Byte first)
            _engineBoots.Span.CopyTo(iv[..4]);

            // next 4 octets (Most Significant Byte first)
            _engineTime.Span.CopyTo(iv[4..8]);

            // last 8 octets (Most Significant Byte first)
            salt.CopyTo(iv[8..16]);

            var paddedCiphertextLength = _aes.GetCiphertextLengthCfb(
                encryptedPdu.Length, 
                PaddingMode.Zeros, 
                128);

            ReadOnlySpan<byte> ciphertext = encryptedPdu.Span;

            if (encryptedPdu.Length != paddedCiphertextLength)
            {
                encryptedPdu.Span.CopyTo(_paddingBuffer);
                ciphertext = _paddingBuffer[..paddedCiphertextLength];
            }

            return _aes.DecryptCfb(
                ciphertext,
                iv,
                PaddingMode.Zeros,
                128);
        }

        public void Dispose()
        {
            _aes.Dispose();

            ArrayPool<byte>.Shared.Return(
                _bufferBackArray,
                clearArray: true);

            ArrayPool<byte>.Shared.Return(
                _paddingBuffer,
                clearArray: true);
        }
    }
}
