using DotNetSnmp.Asn1.Serialization;
using System.Formats.Asn1;

namespace DotNetSnmp.Common.Definitions
{
    public abstract class SnmpMessage: IAsnSerializable
    {
        abstract public ProtocolVersion ProtocolVersion { get; }

        abstract public void WriteTo(AsnWriter writer);
    }
}
