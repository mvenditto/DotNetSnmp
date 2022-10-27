namespace DotNetSnmp.Common.Definitions
{
    public enum SecurityLevel: byte
    {
        None = 0,
        AuthOnly = 1,
        PrivOnly = 2,
        AuthAndPriv = 3
    }
}
