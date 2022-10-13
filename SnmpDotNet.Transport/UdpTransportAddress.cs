using System.Net;
using System.Net.Sockets;

namespace SnmpDotNet.Transport
{
    public class UdpTransportAddress : InetTransportAddress
    {
        public override AddressFamily ProtocolFamilty => AddressFamily.InterNetwork;

        public override SocketType SocketType => SocketType.Dgram;

        public int Port => Endpoint?.Port ?? 0;

        public override SocketAddress SocketAddress
        {
            get 
            {
                if (Endpoint == null)
                {
                    throw new InvalidOperationException();
                }

                return Endpoint!.Serialize();
            }
        }
        public UdpTransportAddress()
        {
            
        }

        public UdpTransportAddress(int port)
        {
            Endpoint = new(IPAddress.Loopback, port);
        }

        public UdpTransportAddress(IPEndPoint endpoint)
        {
            Endpoint = endpoint;
        }

        public UdpTransportAddress(string address, int port)
        {
            Endpoint = new IPEndPoint(
                IPAddress.Parse(address), 
                port);
        }
    }
}