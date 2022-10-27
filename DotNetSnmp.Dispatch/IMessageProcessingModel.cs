using DotNetSnmp.Common.Definitions;
using DotNetSnmp.Transport.Targets;
using System.Net;

namespace DotNetSnmp.Client
{
    public interface IMessageProcessingModel
    {
        bool IsProtocolVersionSupported(ProtocolVersion version);

        bool TryPrepareOutgoingMessage(
            ISnmpTarget target,
            Pdu pdu,
            in ReadOnlyMemory<byte> secEngineId,
            out int sendPduHandle,
            out SnmpMessage outgoingMessage,
            out MessageProcessingResult result,
            bool expectResponse);

        bool TryPrepareDataElements(
            in ReadOnlyMemory<byte> incomingMessage,
            out string securityName,
            out SecurityLevel securityLevel,
            out SecurityModel securityModel,
            out Pdu pdu,
            out int sendPduHandle,
            out MessageProcessingResult result);
    }
}
