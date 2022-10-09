using SnmpDotNet.Asn1.Serialization;
using SnmpDotNet.Asn1.SyntaxObjects;
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace SnmpDotNet.Test
{
    public class TypesEncodeDecode
    {
        private static AsnReader GetReader(string berHexString)
        {
            return new AsnReader(
                Convert.FromHexString(berHexString), 
                AsnEncodingRules.BER);
        }

        private string ToHexString(IAsnSerializable asns)
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);
            asns.WriteTo(writer);
            return Convert.ToHexString(writer.Encode());
        }

        [Fact]
        public void EncodeDecode_Integer32()
        {
            var hexBer = "02012A";
            var reader = GetReader(hexBer); // 42
            var i32 = Integer32.ReadFrom(reader);
            Assert.Equal(42, i32.Value);
            Assert.Equal(hexBer, ToHexString(i32));
        }

        [Fact]
        public void EncodeDecode_Counter64()
        {
            var hexBer = "460900FFFFFFFFFFFFFFFE";
            var reader = GetReader(hexBer); // 18446744073709551614
            var counter64 = Counter64.ReadFrom(reader);
            Assert.Equal(18446744073709551614, counter64.Value);
            Assert.Equal(hexBer, ToHexString(counter64));
        }

        [Fact]
        public void EncodeDecode_OpaqueInteger64()
        {
            var hexBer = "440B9F7A087FFFFFFFFFFFFFFF";
            var reader = GetReader(hexBer); // 9223372036854775807 
            var opaqueInt64 = OpaqueInteger64.ReadFrom(reader);
            Assert.Equal(9223372036854775807, opaqueInt64.Value);
            Assert.Equal(hexBer, ToHexString(opaqueInt64));
        }
    }
}
