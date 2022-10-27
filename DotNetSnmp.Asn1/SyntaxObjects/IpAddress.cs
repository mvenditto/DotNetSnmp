using DotNetSnmp.Asn1.Serialization;
using System.Formats.Asn1;
using System.Text;

namespace DotNetSnmp.Asn1.SyntaxObjects
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

        public IpAddress(System.Net.IPAddress address)
        {
            AddressBytes = address.GetAddressBytes();
        }

        public void WriteTo(AsnWriter writer)
        {
            writer.WriteOctetString(
                AddressBytes,
                tag: AsnTypes.IpAddress);
        }

        public static IpAddress ReadFrom(AsnReader reader)
        {
            var octets = reader.ReadOctetString(
                expectedTag: AsnTypes.IpAddress);
            return new(octets);
        }

        public void Deconstruct(out System.Net.IPAddress address)
        {
            address = new System.Net.IPAddress(AddressBytes);
        }

        public override string ToString()
        {
            var ip = AddressBytes;
            return $"IpAddress: {ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}";
        }
    }
}
