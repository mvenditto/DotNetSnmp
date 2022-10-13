using System.Net;
using System.Net.Sockets;

namespace SnmpDotNet.Transport
{
    public abstract class TransportIpAddress: IAddress
    {
        protected IPEndPoint? _endpoint;

        public abstract AddressFamily ProtocolFamilty { get; }

        public abstract SocketAddress SocketAddress { get; }

        public abstract SocketType SocketType { get; }

        public byte[] GetAddressBytes()
        {
            if (_endpoint == null)
            {
                throw new InvalidOperationException();
            }

            return _endpoint!.Address.GetAddressBytes();
        }

        public bool IsValid() => _endpoint != null;
    }
}