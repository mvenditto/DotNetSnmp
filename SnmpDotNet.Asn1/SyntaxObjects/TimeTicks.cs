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
            var timeticks = Value;
            var centiseconds = timeticks % 100;
            timeticks /= 100;
            var days = timeticks / (60 * 60 * 24);
            timeticks %= (60 * 60 * 24);
            var hours = timeticks / (60 * 60);
            timeticks %= (60 * 60);
            var minutes = timeticks / 60;
            var seconds = timeticks % 60;

            return string.Format(
                "TimeTicks: ({5}) {0}:{1}:{2}:{3}.{4}",
                days, hours, minutes, seconds, centiseconds, Value);
        }

        public static implicit operator uint(TimeTicks t) => t.Value;
    }
}
