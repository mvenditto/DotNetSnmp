using System.Net;
using System.Net.Sockets;

namespace SnmpDotNet.Transport
{
    public class UdpClientTransport : ITransport<UdpTransportAddress>
    {
        public UdpTransportAddress Address { get; init; }

        public int MaxIncomingMessageSize { get; set; }

        public int Timeout { get; set; } = 5000;

        public int MaxRetries { get; set; } = 0;

        private readonly UdpClient _udpClient;

        public UdpClientTransport(UdpTransportAddress address)
        {
            Address = address;
            _udpClient = new UdpClient(Address.Endpoint);
        }

        public UdpClientTransport()
        {
            var endpoint = new IPEndPoint(IPAddress.Any, 0);
            Address = new UdpTransportAddress(endpoint);
            _udpClient = new UdpClient(endpoint);
        }

        public ValueTask<int> SendMessageAsync(
            UdpTransportAddress address, 
            ReadOnlyMemory<byte> message,
            CancellationToken cancellationToken = default)
        {
            return _udpClient.SendAsync(
                message, 
                cancellationToken: cancellationToken, 
                endPoint: address.Endpoint);
        }

        public int SendMessage(
            UdpTransportAddress address, 
            ReadOnlySpan<byte> message)
        {
            return _udpClient.Send(message, address.Endpoint);
        }
    }
}