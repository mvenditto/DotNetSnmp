using System.Net;
using System.Net.Sockets;

namespace SnmpDotNet.Transport
{
    public interface ITransportAddress
    {
        AddressFamily ProtocolFamilty { get; }

        SocketAddress SocketAddress { get; }

        bool IsValid();
    }
}