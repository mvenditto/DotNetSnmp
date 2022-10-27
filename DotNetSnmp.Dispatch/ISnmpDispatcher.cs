using DotNetSnmp.Common.Definitions;
using DotNetSnmp.Transport;
using DotNetSnmp.Transport.Targets;
using System.Net;

namespace DotNetSnmp.Client
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
