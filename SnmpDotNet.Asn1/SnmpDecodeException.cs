using System.Runtime.Serialization;

namespace SnmpDotNet.Asn1.Serialization
{
    public class SnmpDecodeException : Exception
    {
        public SnmpDecodeException(string? message) : base(message)
        {
        }
    }
}
