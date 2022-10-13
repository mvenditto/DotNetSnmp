namespace SnmpDotNet.Transport
{
    [Flags]
    public enum TransportMode
    {
        Receive = 1,
        Send = 2,
        Any = Receive | Send,
    }
}