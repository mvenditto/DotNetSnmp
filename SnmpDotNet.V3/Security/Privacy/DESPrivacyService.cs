using SnmpDotNet.Common.Helpers;
using System.Buffers;
using System.Security.Cryptography;

namespace SnmpDotNet.Protocol.V3.Security.Privacy
{
    public class DESPrivacyService : IPrivacyService, IDisposable
    {
        public int PrivacyParametersLength => 8;

        private readonly DES _des;

        private readonly byte[] _bufferBackArray;

        private readonly byte[] _paddingBuffer;

        private Memory<byte> _privacyKey;

        private Memory<byte> _engineBoots;

        private int _salt = -1;

        public DESPrivacyService(
            in byte[] privacyKey,
            in int engineBoots)
        {
            if (privacyKey.Length < 16)
            {
                throw new ArgumentException("privKey for DES-CBC must be 16 bytes.");
            }

            _des = DES.Create();

            _bufferBackArray = ArrayPool<byte>.Shared.Rent(20);

            _paddingBuffer = ArrayPool<byte>.Shared.Rent(65507);

            _privacyKey = (Memory<byte>)_bufferBackArray[..16];

            _engineBoots = (Memory<byte>)_bufferBackArray[16..20];

            UpdateEngineBoots(engineBoots);

            privacyKey.CopyTo(_privacyKey);

            _des.Key = _privacyKey[..8].ToArray();
        }

        public void UpdateEngineBoots(int authoritativeEngineBoots)
        {
            BinaryHelpers.CopyBytesMostSignificantFirst(
                authoritativeEngineBoots, 
                _engineBoots.Span);
        }

        public void UpdateEngineTime(int authoritativeEngineBoots)
        {
            // no-op
        }

        private int GetNextSalt()
        {
            if (_salt < 0)
            {
                _salt = Random.Shared.Next();
                return _salt;
            }

            _salt = (_salt + 1) % int.MaxValue;

            return _salt;
        }

        public int EncryptScopedPdu(
            in ReadOnlyMemory<byte> scopedPdu,
            Span<byte> privParameters,
            Span<byte> encryptedScopedPdu)
        {
            // generate an 8-octet salt value
            var saltValue = GetNextSalt();

            _engineBoots.Span.CopyTo(privParameters);

            BinaryHelpers.CopyBytesMostSignificantFirst(
                saltValue, 
                privParameters);

            var salt = privParameters;

            // preIV = last 8 octets of privacyKey
            Span<byte> preIv = _privacyKey[8..16].Span;

            // final IV
            Span<byte> iv = stackalloc byte[8];

            // XOR pre-iv with salt
            for (int i = 0; i < 8; i++)
            {
                iv[i] = (byte)(salt[i] ^ preIv[i]);
            }

            return _des.EncryptCbc(
                scopedPdu.Span,
                iv,
                encryptedScopedPdu,
                PaddingMode.Zeros);
        }

        public Memory<byte> DecryptScopedPdu(
            ReadOnlyMemory<byte> encryptedPdu,
            ReadOnlyMemory<byte> privParameters)
        {
            // preIV = last 8 octets of privacyKey
            Span<byte> preIv = _privacyKey[8..16].Span;

            ReadOnlySpan<byte> salt = privParameters.Span;

            // final IV
            Span<byte> iv = stackalloc byte[8];

            // XOR pre-iv with salt
            for (int i = 0; i < 8; i++)
            {
                iv[i] = (byte)(salt[i] ^ preIv[i]);
            }

            var paddedCiphertextLength = _des.GetCiphertextLengthCbc(
                encryptedPdu.Length,
                PaddingMode.Zeros);

            ReadOnlySpan<byte> ciphertext = encryptedPdu.Span;

            if (encryptedPdu.Length != paddedCiphertextLength)
            {
                encryptedPdu.Span.CopyTo(_paddingBuffer);
                ciphertext = _paddingBuffer[..paddedCiphertextLength];
            }

            return _des.DecryptCbc(
                ciphertext, 
                iv, 
                PaddingMode.Zeros);
        }

        public void Dispose()
        {
            _des.Dispose();

            ArrayPool<byte>.Shared.Return(
                _bufferBackArray,
                clearArray: true);

            ArrayPool<byte>.Shared.Return(
                _paddingBuffer,
                clearArray: true);
        }
    }
}
