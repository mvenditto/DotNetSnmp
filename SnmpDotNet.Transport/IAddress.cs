using System.Net;
using System.Net.Sockets;

namespace SnmpDotNet.Transport
{
    public interface IAddress
    {
        AddressFamily ProtocolFamilty { get; }

        SocketAddress SocketAddress { get; }

        bool IsValid();
    }
}