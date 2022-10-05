using SnmpDotNet.Asn1.SyntaxObjects;
using SnmpDotNet.Asn1.Serialization;
using System.Collections;
using System.Diagnostics;
using System.Formats.Asn1;

namespace SnmpDotNet.Asn1.SyntaxObjects
{
    public class VarBindList: IAsnSerializable, IEnumerable<VarBind>
    {
        private readonly IList<VarBind> _variableBindings;

        // rfc 3416 (4.2)
        private const int MaxVariableBindings = 2147483647;

        public VarBindList()
        {
            _variableBindings = new List<VarBind>();
        }

        public VarBindList(params VarBind[] bindings)
        {
            _variableBindings = new List<VarBind>(bindings);
        }

        public VarBindList(params string[] oids)
        {
            _variableBindings = oids.Select(
                oid => new VarBind(oid)).ToList();
        }
        public VarBindList(params ObjectIdentifier[] oids)
        {
            _variableBindings = oids.Select(
                oid => new VarBind(oid)).ToList();
        }

        public VarBindList Add(VarBind varBind)
        {
            _variableBindings.Add(varBind);
            return this;
        }

        public void WriteTo(AsnWriter writer)
        {
            if (_variableBindings == null
                /*|| _variableBindings.Count == 0*/)
            {
                return;
            }

            using (var varBindList = writer.PushSequence())
            {
                foreach (var vb in _variableBindings)
                {
                    vb.WriteTo(writer);
                }
            }
        }

        public static VarBindList ReadFrom(AsnReader reader)
        {
            Span<byte> ipAddressBuff = stackalloc byte[4];

            var sequence = reader.ReadSequence();

            var bindings = new VarBindList();

            if (sequence.HasData == false)
            {
                return bindings;
            }

            var t = sequence.PeekTag();

            while (sequence.HasData)
            {
                var vbSeq = sequence.ReadSequence();
                var oid = vbSeq.ReadObjectIdentifier();
                var tag = vbSeq.PeekTag();

                if (tag == Asn1Tag.PrimitiveOctetString
                    || tag == Asn1Tag.ConstructedOctetString)
                {
                    var octets = vbSeq.ReadOctetString();

                    bindings.Add(
                        new(oid, new OctetString(octets)));
                }
                else if (tag == Asn1Tag.Integer)
                {
                    if (vbSeq.TryReadInt32(out var integer32, AsnTypes.Integer32))
                    {
                        bindings.Add(
                            new(oid, new Integer32(integer32)));
                    }
                }
                else if (tag == AsnTypes.Counter32)
                {
                    if (vbSeq.TryReadUInt32(out var uint32, AsnTypes.Counter32))
                    {
                        bindings.Add(
                            new(oid, new Counter32(uint32)));
                    }
                }
                else if (tag == AsnTypes.Gauge32)
                {
                    if (vbSeq.TryReadUInt32(out var uint32, AsnTypes.Gauge32))
                    {
                        bindings.Add(
                            new(oid, new Gauge32(uint32)));
                    }
                }
                else if (tag == AsnTypes.IpAddress)
                {
                    if (vbSeq.TryReadOctetString(
                        ipAddressBuff,
                        out var len,
                        AsnTypes.IpAddress))
                    {
                        if (len == 4)
                        {
                            bindings.Add(
                                new(oid, new IpAddress(ipAddressBuff.ToArray())));
                        }
                    }
                }
                else if (tag == AsnTypes.TimeTicks)
                {
                    if (vbSeq.TryReadUInt32(out var uint32, AsnTypes.TimeTicks))
                    {
                        bindings.Add(
                            new(oid, new TimeTicks(uint32)));
                    }
                }
                else if (tag == AsnTypes.Unsigned32)
                {
                    if (vbSeq.TryReadUInt32(out var uint32, AsnTypes.Unsigned32))
                    {
                        bindings.Add(
                            new(oid, new Unsigned32(uint32)));
                    }
                }
                else if (tag == Asn1Tag.ObjectIdentifier)
                {
                    var objId = vbSeq.ReadObjectIdentifier();
                    bindings.Add(
                           new(oid, new ObjectIdentifier(objId)));
                }
                else if (tag == SnmpAsnTags.NoSuchObject)
                {
                    bindings.Add(
                           new(oid, new NoSuchObject()));
                }
                else if (tag == SnmpAsnTags.NoSuchInstance)
                {
                    bindings.Add(
                           new(oid, new NoSuchInstance()));
                }
                else if (tag == SnmpAsnTags.EndOfMibView)
                {
                    bindings.Add(
                           new(oid, new EndOfMibView()));
                }
                else if (tag == Asn1Tag.Null)
                {
                    bindings.Add(
                           new(oid, Null.Instance));
                }
                else if (tag == Asn1Tag.Sequence)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    Debug.WriteLine($"Unknown Tag {tag}");
                }
            }

            return bindings;
        }

        public IEnumerator<VarBind> GetEnumerator()
        {
            return _variableBindings?.GetEnumerator()
                ?? Enumerable.Empty<VarBind>().GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}