using System.Net;
using System.Net.Sockets;

namespace SnmpDotNet.Transport
{
    public abstract class InetAddress: IAddress
    {
        public IPEndPoint Endpoint;

        public abstract AddressFamily ProtocolFamilty { get; }

        public abstract SocketAddress SocketAddress { get; }

        public abstract SocketType SocketType { get; }

        public byte[] GetAddressBytes()
        {
            if (Endpoint == null)
            {
                throw new InvalidOperationException();
            }

            return Endpoint!.Address.GetAddressBytes();
        }

        public bool IsValid() => Endpoint != null;
    }
}