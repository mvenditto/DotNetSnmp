using SnmpDotNet.Asn1.Serialization;
using System.Formats.Asn1;

namespace SnmpDotNet.Asn1.SyntaxObjects
{
    /// <summary>
    /// The TimeTicks type represents a non-negative integer which represents
    /// the time, modulo 2^32 (4294967296 decimal), in hundredths of a second
    /// between two epochs.When objects are defined which use this ASN.1
    /// type, the description of the object identifies both of the reference
    /// epochs.
    /// </summary>
    /// <param name="Value"></param>
    public readonly record struct TimeTicks(uint Value) : IAsnSerializable
    {
        public void WriteTo(AsnWriter writer)
        {
            writer.WriteIntegerUnsigned(
                BitConverter.GetBytes(Value),
                tag: SmiAsnTags.TimeTicks);
        }

        public override string ToString()
        {
            var ts = TimeSpan.FromSeconds(Value / 100f);
            var repr = ts.ToString(@"dd\:hh\:mm\:ss\.ff");
            return "TimeTicks: " + repr;
        }

        public static implicit operator uint(TimeTicks t) => t.Value;
    }
}
