using DotNetSnmp.Common.Definitions;
using DotNetSnmp.Protocol.V3.Security.Authentication;
using DotNetSnmp.V3.Security.Privacy;

namespace DotNetSnmp.Transport.Targets
{
    public interface ISnmpTarget
    {
        int Retries { get; }

        int MaxMessageSize { get; }

        long Timeout { get; }

        string SecurityName { get; }

        ProtocolVersion ProtocolVersion { get; }

        SecurityModel SecurityModel { get; }

        SecurityLevel SecurityLevel { get; }

        AuthenticationProtocol AuthProtocol { get; }

        PrivacyProtocol PrivProtocol { get; }

        string? UserPassword { get; }

        ReadOnlyMemory<byte> UserPasswordBytes { get; }
    }
}
