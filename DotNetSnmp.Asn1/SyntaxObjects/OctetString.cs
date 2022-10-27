using DotNetSnmp.Asn1.Serialization;
using System.Formats.Asn1;
using System.Text;

namespace DotNetSnmp.Asn1.SyntaxObjects
{
    public readonly record struct OctetString : IAsnSerializable
    {
        public byte[] Octets { get; }

        public OctetString(string str)
        {
            Octets = Encoding.UTF8.GetBytes(str);
        }

        public OctetString(byte[] octets)
        {
            Octets = octets;
        }

        public override string ToString()
        {
            var hasNonPrintable = Octets.Any(
                c => char.IsControl((char)c) && !char.IsWhiteSpace((char)c));

            if (hasNonPrintable == false)
            {
                return "String: " + Encoding.UTF8.GetString(Octets);
            }

            var hex = Convert.ToHexString(Octets)
                          .Chunk(2)
                          .Select(c => string.Concat(c))
                          .Aggregate((a, b) => a + " " + b);

            return "HexString: " + hex;
        }

        public void WriteTo(AsnWriter writer)
        {
            writer.WriteOctetString(Octets);
        }

        public static OctetString ReadFrom(AsnReader reader)
        {
            var octets = reader.ReadOctetString();
            return new(octets);
        }

        public static implicit operator string(OctetString o) => o.ToString();
    }
}
