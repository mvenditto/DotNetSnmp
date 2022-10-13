using System.Net;
using System.Net.Sockets;

namespace SnmpDotNet.Transport
{
    public class UdpClientTransport : ITransport<UdpAddress>
    {
        public UdpAddress Address { get; init; }

        public int MaxIncomingMessageSize { get; set; }

        public TransportMode TransportMode => TransportMode.Any;

        public int Timeout { get; set; } = 5000;

        public int MaxRetries { get; set; } = 0;

        private readonly UdpClient _udpClient;

        public UdpClientTransport(UdpAddress address)
        {
            Address = address;
            _udpClient = new UdpClient(Address.Endpoint);
        }

        public UdpClientTransport()
        {
            var endpoint = new IPEndPoint(IPAddress.Any, 0);
            Address = new UdpAddress(endpoint);
            _udpClient = new UdpClient(endpoint);
        }

        public ValueTask<int> SendMessageAsync(
            UdpAddress address, 
            ReadOnlyMemory<byte> message,
            CancellationToken cancellationToken = default)
        {
            return _udpClient.SendAsync(
                message, 
                cancellationToken: cancellationToken, 
                endPoint: address.Endpoint);
        }

        public int SendMessage(
            UdpAddress address, 
            ReadOnlySpan<byte> message)
        {
            return _udpClient.Send(message, address.Endpoint);
        }
    }
}