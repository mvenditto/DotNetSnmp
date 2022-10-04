﻿using SnmpDotNet.Asn1.Serialization;
using System.Formats.Asn1;

namespace SnmpDotNet.Asn1.SyntaxObjects
{
    public readonly record struct NoSuchObject : IAsnSerializable
    {
        public void WriteTo(AsnWriter writer)
        {
            writer.WriteNull(tag: SnmpAsnTags.NoSuchObject);
        }
    }
}