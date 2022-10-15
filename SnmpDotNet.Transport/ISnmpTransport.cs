using System.Net;

namespace SnmpDotNet.Transport
{
    public interface ISnmpTransport
    {
        ValueTask Listen();

        ValueTask<int> SendMessageAsync(
            IPEndPoint targetEndpoint,
            ReadOnlyMemory<byte> message,
            CancellationToken cancellationToken = default);

        int SendMessage(
            IPEndPoint targetEndpoint,
            ReadOnlySpan<byte> message);
    }
}