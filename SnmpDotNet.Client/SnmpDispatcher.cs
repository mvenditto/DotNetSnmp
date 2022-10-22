using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Protocol.V1;
using SnmpDotNet.Protocol.V2;
using SnmpDotNet.Transport;
using SnmpDotNet.Transport.Targets;
using SnmpDotNet.Asn1;
using System.Net;
using System.Formats.Asn1;

namespace SnmpDotNet.Client
{
    public class SnmpDispatcher : ISnmpDispatcher
    {
        public async ValueTask<Pdu> SendPdu(
            ISnmpTransport transport, 
            ISnmpTarget target, 
            IPEndPoint targetAddress,
            Pdu pdu, 
            bool expectResponse = true,
            CancellationToken cancellationToken=default)
        {
            var targetVersion = target.ProtocolVersion;

            SnmpMessage outgoingMessge;

            if (pdu.RequestId <= 0)
            {
                pdu.RequestId = Random.Shared.Next();
            }

            if (targetVersion == ProtocolVersion.SnmpV1)
            {
                outgoingMessge = new SnmpV1Message
                {
                    Community = target.SecurityName,
                    Pdu = pdu
                };
            }
            else if (targetVersion == ProtocolVersion.SnmpV2c)
            {
                outgoingMessge = new SnmpV2Message
                {
                    Community = target.SecurityName,
                    Pdu = pdu
                };
            }
            else
            {
                throw new NotImplementedException();
            }

            var sendBytes = await transport.SendAsync(
                outgoingMessge.Encode(),
                targetAddress,
                cancellationToken);

            var incomingData = await transport.ReceiveAsync(
                targetAddress, 
                cancellationToken);

            var reader = new AsnReader(incomingData, AsnEncodingRules.BER);

            Pdu receivedPdu;

            if (targetVersion == ProtocolVersion.SnmpV1)
            {
                var incomingMessage = SnmpV1Message.ReadFrom(reader);
                receivedPdu = incomingMessage.Pdu;
            }
            else if (targetVersion == ProtocolVersion.SnmpV2c)
            {
                var incomingMessage = SnmpV2Message.ReadFrom(reader);
                receivedPdu = incomingMessage.Pdu;
            }
            else
            {
                throw new NotImplementedException();
            }

            if (receivedPdu?.RequestId != pdu.RequestId)
            {
                throw new Exception("Mismatched RequestID!");
            }

            return receivedPdu;
        }
    }
}
