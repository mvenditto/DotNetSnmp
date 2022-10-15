using SnmpDotNet.Common.Definitions;

namespace SnmpDotNet.Transport.Targets
{
    public interface ISnmpTarget
    {
        int Retries { get; }

        int MaxRequestPduBytes { get; }

        long Timeout { get; }

        string SecurityName { get; }

        ProtocolVersion ProtocolVersion { get; }

        SecurityModel Security { get; }

        SecurityLevel SecurityLevel { get; }
    }
}
