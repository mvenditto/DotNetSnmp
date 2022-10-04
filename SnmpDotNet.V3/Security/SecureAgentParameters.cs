using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SnmpDotNet.Protocol.V3.Security
{
    public class SecureAgentParameters
    {
        private string _securityName;
        private byte[] _securityNameBytes;
        private byte[] _userPassphraseBytes;

        public HashAlgorithmName? HashAlgorithm { get; set; }

        public string SecurityName
        {
            get => _securityName;
            set
            {
                _securityName = value;
                _securityNameBytes = Encoding.UTF8.GetBytes(value);
            }
        }

        public string UserPassphrase
        {
            set
            {
                _userPassphraseBytes = Encoding.UTF8.GetBytes(value);
            }
        }

        public ReadOnlyMemory<byte> UserPassphraseBytes => _userPassphraseBytes;
    }
}
