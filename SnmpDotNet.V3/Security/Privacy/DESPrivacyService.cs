using System.Buffers;
using System.Security.Cryptography;

namespace SnmpDotNet.Protocol.V3.Security.Privacy
{
    public class DESPrivacyService: IPrivacyService
    {
        public int PrivacyParametersLength => 8;

        private readonly DES _des;

        private readonly byte[] _bufferBackArray;

        private Memory<byte> _privacyKey;

        private readonly byte[] _engineBoots;

        private int _salt = -1;

        public DESPrivacyService(
            in byte[] privacyKey,
            in int engineBoots)
        {
            if (privacyKey.Length < 16)
            {
                throw new ArgumentException("privKey for DES-CBC must be 16 bytes.");
            }

            _engineBoots = BitConverter.GetBytes(engineBoots)
                .Reverse() // big-endian
                .ToArray();

            _des = DES.Create();

            _bufferBackArray = ArrayPool<byte>.Shared.Rent(16);

            _privacyKey = (Memory<byte>) _bufferBackArray;

            privacyKey.CopyTo(_privacyKey);

            _des.Key = _privacyKey[..8].ToArray();
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
            var saltValue = BitConverter.GetBytes(42); //GetNextSalt()

            _engineBoots[..4].CopyTo(privParameters);

            privParameters[7] = saltValue[0];
            privParameters[6] = saltValue[1];
            privParameters[5] = saltValue[2];
            privParameters[4] = saltValue[3];

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

        public void Dispose()
        {
            _des.Dispose();

            ArrayPool<byte>.Shared.Return(
                _bufferBackArray, 
                clearArray: true);
        }
    }
}
