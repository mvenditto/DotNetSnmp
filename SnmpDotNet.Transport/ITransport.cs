﻿namespace SnmpDotNet.Transport
{
    public interface ITransport<A> where A: ITransportAddress
    {
        A Address { get; }

        int MaxIncomingMessageSize { get; set; }

        int Timeout { get; set; }

        int MaxRetries { get; set; }

        ValueTask<int> SendMessageAsync(
            A address,
            ReadOnlyMemory<byte> message,
            CancellationToken cancellationToken = default);

        int SendMessage(
            A address,
            ReadOnlySpan<byte> message);
    }
}