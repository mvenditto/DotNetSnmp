using System.Formats.Asn1;

namespace SnmpDotNet.Asn1.Serialization
{
    public interface IAsnSerializable
    {
        public void WriteTo(AsnWriter writer);
    }
}
