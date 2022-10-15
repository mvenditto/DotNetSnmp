using System.Net;
using System.Net.Sockets;

namespace SnmpDotNet.Transport
{
    public class BasicUdpTransport : ISnmpTransport
    {
        private readonly UdpClient _udpClient;

        public UdpClient UdpClient => _udpClient;

        public IPEndPoint ListenEndpoint {get; init; }

        public BasicUdpTransport(IPEndPoint listenEndpoint)
        {
            ListenEndpoint = listenEndpoint;
            _udpClient = new UdpClient(listenEndpoint);
        }

        public BasicUdpTransport(): this(new IPEndPoint(IPAddress.Any, 0))
        {

        }

        public ValueTask Listen()
        {
            _udpClient.Connect(ListenEndpoint);
            return ValueTask.CompletedTask;
        }

        public ValueTask<int> SendMessageAsync(
            IPEndPoint targetEndpoint,
            ReadOnlyMemory<byte> message,
            CancellationToken cancellationToken = default)
        {
            return _udpClient.SendAsync(
                message,
                cancellationToken: cancellationToken,
                endPoint: targetEndpoint);
        }

        public int SendMessage(
            IPEndPoint targetEndpoint,
            ReadOnlySpan<byte> message)
        {
            return _udpClient.Send(message, targetEndpoint);
        }

        public void Close()
        {
            _udpClient.Close();
        }

        public void Dispose()
        {
            GC.SuppressFinalize(this);
            _udpClient.Close();
            _udpClient.Dispose();
        }
    }
}