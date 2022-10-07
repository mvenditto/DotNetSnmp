using SnmpDotNet.Asn1.SyntaxObjects;
using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Protocol.V1;
using System.Formats.Asn1;
using System.Text;
using Xunit;

namespace SnmpDotNet.Test
{
    public class SerializationTest
    {

        [Fact]
        public void DecodeEncodeV1GetRequestMessage()
        {
            var dump = @"Sending 43 bytes to UDP: [127.0.0.1]:161->[0.0.0.0]:0
                0000: 30 29 02 01  00 04 06 70  75 62 6C 69  63 A0 1C 02    0).....public...
                0016: 04 0C BB 47  10 02 01 00  02 01 00 30  0E 30 0C 06    ...G.......0.0..
                0032: 08 2B 06 01  02 01 01 01  00 05 00                    .+.........";

            var messageBytes = Dump.BytesFromHexString(dump);

            var reader = new AsnReader(messageBytes, AsnEncodingRules.BER);

            var message = SnmpV1Message.ReadFrom(reader);

            Assert.NotNull(message);

            Assert.Equal(
                ProtocolVersion.SnmpV1,  
                message.ProtocolVersion);

            Assert.Equal("public", message.Community);

            Assert.NotNull(message.Pdu);

            Assert.IsType<GetRequestPdu>(message.Pdu);

            Assert.NotNull(message.Pdu.VariableBindings);

            var varbind = message!.Pdu.VariableBindings!.FirstOrDefault();

            Assert.Equal("1.3.6.1.2.1.1.1.0", varbind.Name);

            Assert.IsType<Null>(varbind.Value);

            var writer = new AsnWriter(AsnEncodingRules.BER);

            message.WriteTo(writer);

            var encoded = writer.Encode();

            Assert.Equal(messageBytes, encoded);
        }

        [Fact]
        public void DecodeEncodeV1GetResponseMessage()
        {
            var dump = @"Received 63 byte packet from UDP: [127.0.0.1]:161->[0.0.0.0]:39239
                0000: 30 3D 02 01  00 04 06 70  75 62 6C 69  63 A2 30 02    0=.....public.0.
                0016: 04 0C BB 47  10 02 01 00  02 01 00 30  22 30 20 06    ...G.......0""0.
                0032: 08 2B 06 01  02 01 01 01  00 04 14 4E  65 74 53 6E    .+.........NetSn
                0048: 6D 70 54 65  73 74 43 6F  6E 74 61 69  6E 65 72       mpTestContainer";

            var messageBytes = Dump.BytesFromHexString(dump);

            var reader = new AsnReader(messageBytes, AsnEncodingRules.BER);

            var message = SnmpV1Message.ReadFrom(reader);

            Assert.NotNull(message);

            Assert.Equal(
                ProtocolVersion.SnmpV1,
                message.ProtocolVersion);

            Assert.Equal("public", message.Community);

            Assert.NotNull(message.Pdu);

            Assert.IsType<GetResponsePdu>(message.Pdu);

            Assert.NotNull(message.Pdu.VariableBindings);

            var varbind = message!.Pdu.VariableBindings!.FirstOrDefault();

            Assert.Equal("1.3.6.1.2.1.1.1.0", varbind.Name);

            Assert.IsType<OctetString>(varbind.Value);

            var octetString = (OctetString) varbind.Value;

            Assert.Equal(
                "NetSnmpTestContainer", 
                Encoding.ASCII.GetString(octetString.Octets));

            var writer = new AsnWriter(AsnEncodingRules.BER);

            message.WriteTo(writer);

            var encoded = writer.Encode();

            Assert.Equal(messageBytes, encoded);
        }

        [Fact]
        public void DecodeEncodeV1GetNextRequestMessage()
        {
            var dump = @"Sending 42 bytes to UDP: [127.0.0.1]:161->[0.0.0.0]:0
            0000: 30 28 02 01  00 04 06 70  75 62 6C 69  63 A1 1B 02    0(.....public...
            0016: 04 5E 4C 7A  AE 02 01 00  02 01 00 30  0D 30 0B 06    .^Lz.......0.0..
            0032: 07 2B 06 01  02 01 01 01  05 00                       .+........";

            var messageBytes = Dump.BytesFromHexString(dump);

            var reader = new AsnReader(messageBytes, AsnEncodingRules.BER);

            var message = SnmpV1Message.ReadFrom(reader);

            Assert.NotNull(message);

            Assert.Equal(
                ProtocolVersion.SnmpV1,
                message.ProtocolVersion);

            Assert.Equal("public", message.Community);

            Assert.NotNull(message.Pdu);

            Assert.IsType<GetNextRequestPdu>(message.Pdu);

            Assert.NotNull(message.Pdu.VariableBindings);

            var varbind = message!.Pdu.VariableBindings!.FirstOrDefault();

            Assert.Equal("1.3.6.1.2.1.1.1", varbind.Name);

            Assert.IsType<Null>(varbind.Value);

            var writer = new AsnWriter(AsnEncodingRules.BER);

            message.WriteTo(writer);

            var encoded = writer.Encode();

            Assert.Equal(messageBytes, encoded);
        }
    }
}