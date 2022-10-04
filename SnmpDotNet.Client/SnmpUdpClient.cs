using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Protocol.V1;
using SnmpDotNet.Protocol.V3;
using SnmpDotNet.Protocol.V3.Security;
using System.Buffers;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SnmpDotNet.Client
{
    public class SnmpUdpClient : IDisposable
    {
        private readonly UdpClient _udpClient;

        private readonly IPEndPoint _bindAddress;

        private readonly AsnWriter _asnWriter;

        public SnmpUdpClient(
            IPEndPoint snmpTarget,
            IPEndPoint? bindAddress=null)
        {
            _bindAddress = bindAddress 
                ?? new IPEndPoint(IPAddress.Any, 0); // listen on all interfaces

            _udpClient = new UdpClient(_bindAddress);

            _udpClient.Connect(snmpTarget);

            _asnWriter = new AsnWriter(AsnEncodingRules.BER);
        }

        public async Task<byte[]> SendAsync(
            SnmpMessage message, 
            CancellationToken cancellationToken = default)
        {
            _asnWriter.Reset();

            message.WriteTo(_asnWriter);

            var packetLength = _asnWriter.GetEncodedLength();

            byte[] buffer = ArrayPool<byte>.Shared.Rent(packetLength);

            _asnWriter.Encode(buffer);

            var serializedMsg = (ReadOnlyMemory<byte>) buffer.AsMemory()[..packetLength];

            if (message.ProtocolVersion == ProtocolVersion.SnmpV3)
            {
                var v3Message = (SnmpV3Message) message;
                var usm = v3Message.SecurityParameters;
                var authService = usm.AuthenticationService;

                if (v3Message.GlobalData.MsgFlags.HasFlag(MsgFlags.Auth) && authService != null)
                {
                    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.MD5);

                    if (usm.AuthParams.IsEmpty)
                    {
                        usm.AuthParams = new byte[authService.TruncatedDigestSize];
                    }

                    var authKey = new byte[hash.HashLengthInBytes];

                    KeyUtils.GenerateLocalizedKey(
                        "Password1".GetBytesMemoryOrDefault(Encoding.UTF8),
                        usm.AuthoritativeEngineId,
                        hash,
                        authKey
                    );

                    await authService.AuthenticateOutgoingMsg(
                        authKey, 
                        serializedMsg.Span, 
                        usm.AuthParams.Span);

                    _asnWriter.Reset();
                    v3Message.WriteTo(_asnWriter);
                    _asnWriter.Encode(buffer);
                }
            }

            _ = await _udpClient.SendAsync(
                serializedMsg, 
                cancellationToken).ConfigureAwait(false);

            ArrayPool<byte>.Shared.Return(buffer);

            var recvResult = await _udpClient.ReceiveAsync(cancellationToken);

            return recvResult.Buffer;
        }

        public async Task<GetResponsePdu> GetAsync(
            SnmpMessage message,
            CancellationToken cancellationToken = default)
        {
            var data = await SendAsync(
                message, 
                cancellationToken).ConfigureAwait(false);

            var reader = new AsnReader(data, AsnEncodingRules.BER);

            var msgSeq = reader.ReadSequence();

            msgSeq.TryReadInt32(out var msgVersion);

            var version = (ProtocolVersion)msgVersion;

            if (version == ProtocolVersion.SnmpV1
                || version == ProtocolVersion.SnmpV2c)
            {
                var community = msgSeq.ReadOctetString();
            }    

            return GetResponsePdu.ReadFrom(msgSeq);
        }
        public Task<GetResponsePdu> GetNext(
            SnmpMessage message,
            CancellationToken cancellationToken = default)
            => GetAsync(message, cancellationToken);

        void IDisposable.Dispose()
        {
            GC.SuppressFinalize(this);
            _udpClient?.Dispose();
        }
    }
}
