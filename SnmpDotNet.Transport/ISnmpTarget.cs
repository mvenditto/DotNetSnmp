using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Protocol.V3.Security.Authentication;
using SnmpDotNet.V3.Security.Privacy;

namespace SnmpDotNet.Transport.Targets
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
