namespace SnmpDotNet.Transport
{
    public interface ITransport<A> where A: IAddress
    {
        A Address { get; set; }

        int MaxIncomingMessageSize { get; }

        TransportMode TransportMode { get;  }

        int Timeout { get; set; }

        int MaxRetries { get; set; }
    }
}