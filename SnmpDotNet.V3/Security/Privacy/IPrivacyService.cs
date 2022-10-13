namespace SnmpDotNet.Protocol.V3.Security.Privacy
{
    public interface IPrivacyService
    {
        public int PrivacyParametersLength { get; }

        Memory<byte> DecryptScopedPdu(ReadOnlyMemory<byte> encryptedPdu, ReadOnlyMemory<byte> privParameters);

        int EncryptScopedPdu(in ReadOnlyMemory<byte> scopedPdu, Span<byte> privParameters, Span<byte> encryptedScopedPdu);

        void UpdateEngineBoots(int authoritativeEngineBoots);

        void UpdateEngineTime(int authoritativeEngineBoots);
    }

}
