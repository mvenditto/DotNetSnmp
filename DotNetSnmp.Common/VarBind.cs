using DotNetSnmp.Asn1.Serialization;
using System.Formats.Asn1;

namespace DotNetSnmp.Asn1.SyntaxObjects
{
    public readonly record struct VarBind: IAsnSerializable
    {
        public readonly ObjectIdentifier Name { get;  }

        public readonly IAsnSerializable Value { get; }

        public VarBind(string oid, IAsnSerializable? value = null)
        {
            Name = new ObjectIdentifier(oid);
            Value = value ?? Null.Instance;
        }

        public void WriteTo(AsnWriter writer)
        {
            using (var varBind = writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Name.Oid);

                if (Value == null)
                {
                    writer.WriteNull();
                }
                else
                {
                    Value.WriteTo(writer);
                }
            }
        }

        public void Deconstruct(out string name, out object value)
        {
            name = Name;
            value = Value;
        }

        public override string ToString()
        {
            return $"{Name} = {Value}";
        }

        public static explicit operator VarBind(string oid) => new(oid);
    }
}
