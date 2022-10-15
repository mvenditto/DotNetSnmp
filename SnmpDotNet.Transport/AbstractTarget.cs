using SnmpDotNet.Common.Definitions;

namespace SnmpDotNet.Transport.Targets
{
    public abstract record AbstractTarget: ISnmpTarget
    {
        public string SecurityName { get; init; } = string.Empty;

        public int Retries { get; init; } = 0;

        public long Timeout { get; init; } = 0;

        public int MaxRequestPduBytes { get; init; } = 65535;

        public ProtocolVersion ProtocolVersion { get; init; } = ProtocolVersion.SnmpV1;

        public SecurityModel Security { get; init; } = SecurityModel.SnmpV1;

        public SecurityLevel SecurityLevel { get; init; } = SecurityLevel.None;
    }
}
