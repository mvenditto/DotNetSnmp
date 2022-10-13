using System.Net;
using System.Net.Sockets;

namespace SnmpDotNet.Transport
{
    public class UdpAddress : InetAddress
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
        public UdpAddress()
        {
            
        }

        public UdpAddress(int port)
        {
            Endpoint = new(IPAddress.Loopback, port);
        }

        public UdpAddress(IPEndPoint endpoint)
        {
            Endpoint = endpoint;
        }

        public UdpAddress(string address, int port)
        {
            Endpoint = new IPEndPoint(
                IPAddress.Parse(address), 
                port);
        }
    }
}