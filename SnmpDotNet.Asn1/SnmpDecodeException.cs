using System.Runtime.Serialization;

namespace SnmpDotNet.Asn1.Serialization
{
    public class SnmpDecodeException : Exception
    {
        public SnmpDecodeException()
        {
        }

        public SnmpDecodeException(string? message) : base(message)
        {
        }

        public SnmpDecodeException(string? message, Exception? innerException) : base(message, innerException)
        {
        }

        protected SnmpDecodeException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
