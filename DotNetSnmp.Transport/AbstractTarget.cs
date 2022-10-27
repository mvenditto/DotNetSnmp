using DotNetSnmp.Common.Definitions;
using DotNetSnmp.Protocol.V3.Security.Authentication;
using DotNetSnmp.V3.Security.Privacy;
using System.Text;

namespace DotNetSnmp.Transport.Targets
{
    public abstract record AbstractTarget: ISnmpTarget
    {
        private string _userPassword = string.Empty;
        
        private byte[] _userPasswordBytes;

        private ProtocolVersion _protocolVersion;

        private SecurityModel SetSecurityModel(ProtocolVersion version) => version switch
        {
            ProtocolVersion.SnmpV1 => SecurityModel.SnmpV1,
            ProtocolVersion.SnmpV2c => SecurityModel.SnmpV2c,
            ProtocolVersion.SnmpV3 => SecurityModel.Usm,
            _ => throw new NotImplementedException()
        }; 

        public string SecurityName { get; init; } = string.Empty;

        public int Retries { get; init; } = 0;

        public long Timeout { get; init; } = 0;

        public int MaxMessageSize { get; init; } = 65535;

        public ProtocolVersion ProtocolVersion 
        { 
            get => _protocolVersion; 
            init
            {
                _protocolVersion = value;
                SecurityModel = SetSecurityModel(value);
            }
        }

        public SecurityModel SecurityModel { get; private set; } = SecurityModel.SnmpV1;

        public SecurityLevel SecurityLevel { get; init; } = SecurityLevel.None;

        public AuthenticationProtocol AuthProtocol => AuthenticationProtocol.None;

        public PrivacyProtocol PrivProtocol => PrivacyProtocol.None;

        public ReadOnlyMemory<byte> UserPasswordBytes => _userPasswordBytes;

        public string UserPassword 
        {
            get => _userPassword;
            init
            {
                _userPassword = value;
                _userPasswordBytes = Encoding.UTF8.GetBytes(value);
            }
        }
    }
}
