using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Protocol.V1;
using SnmpDotNet.Protocol.V3;
using SnmpDotNet.Protocol.V3.Security;
using SnmpDotNet.Protocol.V3.Security.Authentication;
using SnmpDotNet.Protocol.V3.Security.Privacy;
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

        public async Task<SnmpMessage> SendAsync(
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
                var authProto = usm.AuthenticationProtocol;

                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.MD5);

                var authKey = new byte[hash.HashLengthInBytes];

                KeyUtils.GenerateLocalizedKey(
                    "Password1".GetBytesMemoryOrDefault(Encoding.UTF8),
                    usm.EngineId,
                    hash,
                    authKey
                );
                /*
                if (v3Message.GlobalData.MsgFlags.HasFlag(MsgFlags.Priv))
                {
                    var privProto = usm.PrivacyProtocol;

                    var privService = new DESPrivacyService(authKey, usm.EngineBoots);

                    if (usm.PrivParams.IsEmpty)
                    {
                        usm.PrivParams = new byte[8];
                    }

                    var scopedPduWriter = new AsnWriter(AsnEncodingRules.BER);
                    v3Message.WriteTo(scopedPduWriter);
                    var data = scopedPduWriter.Encode();

                    v3Message.EncryptedScopedPdu = new byte[16];

                    var n = privService.EncryptScopedPdu(
                        data,
                        usm.PrivParams.Span, 
                        v3Message.EncryptedScopedPdu.Span);
                }*/

                if (v3Message.GlobalData.MsgFlags.HasFlag(MsgFlags.Auth) 
                    && authProto != AuthenticationProtocol.None)
                {
                    
                    if (usm.AuthParams.IsEmpty)
                    {
                        usm.AuthParams = new byte[authProto.TruncatedDigestSize()];
                    }

                    var authService = new AuthenticationService(authProto, authKey);

                    await authService.AuthenticateOutgoingMsg(
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

            var reader = new AsnReader(recvResult.Buffer, AsnEncodingRules.BER);

            SnmpMessage msg = message.ProtocolVersion switch
            {
                ProtocolVersion.SnmpV1 
                    => SnmpV1Message.ReadFrom(reader),
                ProtocolVersion.SnmpV2c 
                    => SnmpV2Message.ReadFrom(reader),
                ProtocolVersion.SnmpV3 
                    => SnmpV3Message.ReadFrom(reader),
                _ => throw new NotImplementedException(),
            };

            return msg;
        }

        public async Task<GetResponsePdu> GetAsync(
            SnmpMessage message,
            CancellationToken cancellationToken = default)
        {
            var responseMsg = await SendAsync(
                message, 
                cancellationToken).ConfigureAwait(false);

            if (responseMsg is SnmpV1Message msg1) 
            {
                return (GetResponsePdu) msg1.Pdu;
            }
            else if (responseMsg is SnmpV2Message msg2)
            {
                return (GetResponsePdu) msg2.Pdu;
            }
            else
            {
                return (GetResponsePdu) ((SnmpV3Message)responseMsg).ScopedPdu.Pdu;
            }
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
