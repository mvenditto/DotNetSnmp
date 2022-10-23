using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Protocol.V1;
using SnmpDotNet.Protocol.V3;
using SnmpDotNet.Transport.Targets;
using System.Formats.Asn1;

namespace SnmpDotNet.Client
{
    /// <summary>
    /// The message processing model for SNMPv1.
    /// </summary>
    public class V1MessageProcessingModel : IMessageProcessingModel
    {
        public bool IsProtocolVersionSupported(ProtocolVersion version)
        {
            return version == ProtocolVersion.SnmpV1;
        }

        public bool TryPrepareDataElements(
            in ReadOnlyMemory<byte> incomingMessage, 
            out string securityName, 
            out SecurityLevel securityLevel, 
            out SecurityModel securityModel, 
            out Pdu pdu, 
            out int sendPduHandle, 
            out MessageProcessingResult result)
        {
            result = MessageProcessingResult.Success;
            sendPduHandle = -1;
            securityLevel = SecurityLevel.None;
            securityModel = SecurityModel.SnmpV1;
            securityName = string.Empty;
            pdu = null;

            try
            {
                var reader = new AsnReader(incomingMessage, AsnEncodingRules.BER);
                var message = SnmpV1Message.ReadFrom(reader);
                pdu = message.Pdu;
                sendPduHandle = message.Pdu.RequestId;
                securityName = message.Community;
                securityModel = SecurityModel.SnmpV1;
                return true;
            }
            catch (Exception ex)
            {
                result = MessageProcessingResult.InternalError;
                return false;
            }
        }

        public bool TryPrepareOutgoingMessage(
            ISnmpTarget target,
            Pdu pdu,
            in ReadOnlyMemory<byte> secEngineId,
            out int sendPduHandle, 
            out SnmpMessage outgoingMessage, 
            out MessageProcessingResult result,
            bool expectResponse=true)
        {

            result = MessageProcessingResult.Success;
            sendPduHandle = -1;
            outgoingMessage = null;

            if (pdu == null)
            {
                throw new ArgumentNullException(nameof(pdu));
            }

            if (target.SecurityLevel != SecurityLevel.None
                || target.SecurityModel != SecurityModel.SnmpV1)
            {
                result = MessageProcessingResult.UnsupportedSecurityModel;
                return false;
            }

            if (pdu is ScopedPdu)
            {
                throw new ArgumentException(
                    $"{nameof(pdu)} of type ScopedPdu is not supported by V1MessageProcessingModel");
            }

            if (pdu.RequestId <= 0)
            {
                pdu.RequestId = Random.Shared.Next();
            }

            outgoingMessage = new SnmpV1Message
            {
                Community = target.SecurityName,
                Pdu = pdu
            };

            sendPduHandle = pdu.RequestId;

            return true;
        }
    }
}
