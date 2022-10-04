namespace SnmpDotNet.Protocol.V3.Security
{
    [Flags]
    public enum MsgFlags : byte
    {
        NoAuthNoPriv = 0b00000000,
        Auth = 0b00000001,
        Priv = 0b00000010,
        Reportable = 0b00000100,
        Reserved = 0b00000010,
        AuthNoPriv = Auth,
        AuthPriv = Auth | Priv
    }
}
