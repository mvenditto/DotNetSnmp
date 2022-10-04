using SnmpDotNet.Asn1.Serialization;
using System.Formats.Asn1;
using System.Text;

namespace SnmpDotNet.Asn1.SyntaxObjects
{
    public readonly record struct OctetString : IAsnSerializable
    {
        private readonly byte[] _octets;

        public OctetString(string str)
        {
            _octets = Encoding.UTF8.GetBytes(str);
        }

        public OctetString(byte[] octets)
        {
            _octets = octets;
        }

        public override string ToString()
        {
            var hasNonPrintable = _octets.Any(
                c => char.IsControl((char)c) && !char.IsWhiteSpace((char)c));

            if (hasNonPrintable == false)
            {
                return "String: " + Encoding.UTF8.GetString(_octets);
            }

            var hex = Convert.ToHexString(_octets)
                          .Chunk(2)
                          .Select(c => string.Concat(c))
                          .Aggregate((a, b) => a + " " + b);

            return "HexString: " + hex;
        }

        public void WriteTo(AsnWriter writer)
        {
            writer.WriteOctetString(_octets);
        }

        public static implicit operator string(OctetString o) => o.ToString();
    }
}
