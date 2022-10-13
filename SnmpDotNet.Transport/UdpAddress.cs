using System.Net;
using System.Net.Sockets;

namespace SnmpDotNet.Transport
{
    public class UdpAddress : TransportIpAddress
    {
        public override AddressFamily ProtocolFamilty => AddressFamily.InterNetwork;

        public override SocketType SocketType => SocketType.Dgram;

        public int Port => _endpoint?.Port ?? 0;

        public override SocketAddress SocketAddress
        {
            get 
            {
                if (_endpoint == null)
                {
                    throw new InvalidOperationException();
                }

                return _endpoint!.Serialize();
            }
        }
        public UdpAddress()
        {
            
        }

        public UdpAddress(int port)
        {
            _endpoint = new(IPAddress.Loopback, port);
        }

        public UdpAddress(IPEndPoint endpoint)
        {
            _endpoint = endpoint;
        }

        public UdpAddress(string address, int port)
        {
            _endpoint = new IPEndPoint(
                IPAddress.Parse(address), 
                port);
        }
    }
}