using SnmpDotNet.Asn1.Serialization;
using System.Formats.Asn1;
using System.Net;
using System.Text;

namespace SnmpDotNet.Asn1.SyntaxObjects
{
    /// <summary>
    /// The IpAddress type represents a 32-bit internet address.  It is
    /// represented as an OCTET STRING of length 4, in network byte-order
    /// </summary>
    /// <param name="Value"></param>
    public readonly record struct IpAddress : IAsnSerializable
    {
        public readonly byte[] AddressBytes { get; }

        public IpAddress(string address)
        {
            AddressBytes = Encoding.UTF8.GetBytes(address);
        }

        public IpAddress(byte[] address)
        {
            if (address.Length != 4)
            {
                throw new ArgumentException("IpAddress must be a 4-Length OctetString");
            }

            AddressBytes = address;
        }

        public IpAddress(IPAddress address)
        {
            AddressBytes = address.GetAddressBytes();
        }

        public void WriteTo(AsnWriter writer)
        {
            writer.WriteOctetString(
                AddressBytes,
                tag: SmiAsnTags.IpAddress);
        }

        public void Deconstruct(out IPAddress address)
        {
            address = new IPAddress(AddressBytes);
        }

        public override string ToString()
        {
            var ip = AddressBytes;
            return $"IpAddress: {ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}";
        }
    }
}
