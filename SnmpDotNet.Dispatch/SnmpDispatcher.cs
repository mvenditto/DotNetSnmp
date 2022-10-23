using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Transport;
using SnmpDotNet.Transport.Targets;
using SnmpDotNet.Asn1;
using System.Net;

namespace SnmpDotNet.Client
{
    public class SnmpDispatcher : ISnmpDispatcher
    {
        private IMessageProcessingModel _v1MsgProcModel;
        private IMessageProcessingModel _v2MsgProcModel;
        private IMessageProcessingModel _v3UsmMsgProcModel;

        private IMessageProcessingModel GetMessageProcessingModel(ProtocolVersion version) => version switch
        {
            ProtocolVersion.SnmpV1 => _v1MsgProcModel ??= new V1MessageProcessingModel(),
            ProtocolVersion.SnmpV2c => _v2MsgProcModel ??= new V2MessageProcessingModel(),
            ProtocolVersion.SnmpV3 => _v3UsmMsgProcModel ??= new V3MessageProcessingModel(),
            _ => throw new NotImplementedException(),
        };

        public async ValueTask<Pdu> SendPdu(
            ISnmpTransport transport, 
            ISnmpTarget target, 
            IPEndPoint targetAddress,
            Pdu pdu, 
            bool expectResponse = true,
            CancellationToken cancellationToken=default)
        {
            var mpModel = GetMessageProcessingModel(
                target.ProtocolVersion);

            if (mpModel is V3MessageProcessingModel)
            {
                throw new NotImplementedException();
            }

            if (mpModel.TryPrepareOutgoingMessage(
                target, 
                pdu, 
                ReadOnlyMemory<byte>.Empty, 
                out int pduHandle, 
                out SnmpMessage outgoingMessage, 
                out MessageProcessingResult result, 
                true)) {

                _ = await transport.SendAsync(
                    outgoingMessage.Encode(),
                    targetAddress,
                    cancellationToken);

                var incomingData = await transport.ReceiveAsync(
                    targetAddress,
                    cancellationToken);

                if (mpModel.TryPrepareDataElements(
                    incomingData,
                    out var resSecurityName,
                    out var resSecurityLevel,
                    out var resSecurityModel,
                    out Pdu resPdu,
                    out int resPduHandle,
                    out var resProcessingResult))
                {
                    return resPdu;
                }
                else
                {
                    throw new Exception($"Message processing error: {resProcessingResult}");
                }
            }
            else
            {
                throw new Exception($"Message processing error: {result}");
            }
        }
    }
}
