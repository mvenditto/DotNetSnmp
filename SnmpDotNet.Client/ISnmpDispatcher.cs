using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Transport;
using SnmpDotNet.Transport.Targets;
using System.Net;

namespace SnmpDotNet.Client
{
    public interface ISnmpDispatcher
    {
        public ValueTask<Pdu> SendPdu(
            ISnmpTransport transport,
            ISnmpTarget target,
            IPEndPoint targetAddress,
            Pdu pdu, 
            bool expectResponse,
            CancellationToken cancellationToken
        );
    }
}
