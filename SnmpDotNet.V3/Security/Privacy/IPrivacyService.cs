namespace SnmpDotNet.Protocol.V3.Security.Privacy
{
    public interface IPrivacyService: IDisposable
    {
        public int PrivacyParametersLength { get; }

        int EncryptScopedPdu(
            in ReadOnlyMemory<byte> scopedPdu, 
            Span<byte> privParameters, 
            Span<byte> encryptedScopedPdu);
    }
}
