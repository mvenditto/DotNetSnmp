using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Protocol.V3;
using SnmpDotNet.Protocol.V3.Security;
using System.Formats.Asn1;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace SnmpDotNet.Test
{
    public class AuthenticationTest
    {
        [Fact]
        public void EncodeDecodeReportMessage()
        {
            var dump = @"Sending 63 bytes to UDP: [127.0.0.1]:161->[0.0.0.0]:0
                0000: 30 3D 02 01  03 30 10 02  04 2E 7D 44  EC 02 02 05    0=...0....}D....
                0016: C0 04 01 04  02 01 03 04  10 30 0E 04  00 02 01 00    .........0......
                0032: 02 01 00 04  00 04 00 04  00 30 14 04  00 04 00 A0    .........0......
                0048: 0E 02 04 63  D4 A9 15 02  01 00 02 01  00 30 00       ...c.........0.";

            var messageBytes = Dump.BytesFromHexString(dump);

            var reader = new AsnReader(messageBytes, AsnEncodingRules.BER);

            var message = SnmpV3Message.ReadFrom(reader);

            Assert.NotNull(message);

            Assert.Equal(
                ProtocolVersion.SnmpV3,
                message.ProtocolVersion);

            Assert.Equal(MsgFlags.Reportable, message.GlobalData.MsgFlags);

            var usmSecParams = message.SecurityParameters;

            Assert.NotNull(usmSecParams);

            Assert.Empty(usmSecParams.EngineId.ToArray());

            Assert.Equal(0, usmSecParams.EngineBoots);

            Assert.Equal(SecurityModel.Usm, message.GlobalData.MsgSecurityModel);
        }

        [Fact]
        public void EncodeDecodeReportResponseMessage()
        {
            var dump = @"Received 116 byte packet from UDP: [127.0.0.1]:161->[0.0.0.0]:57524
                0000: 30 72 02 01  03 30 11 02  04 2E 7D 44  EC 02 03 00    0r...0....}D....
                0016: FF E3 04 01  00 02 01 03  04 22 30 20  04 11 80 00    .........""0....
                0032: 1F 88 80 96  14 8B 64 91  7A 40 63 00  00 00 00 02    ......d.z@c.....
                0048: 01 01 02 02  00 D4 04 00  04 00 04 00  30 36 04 11    ............06..
                0064: 80 00 1F 88  80 96 14 8B  64 91 7A 40  63 00 00 00    ........d.z@c...
                0080: 00 04 00 A8  1F 02 04 63  D4 A9 15 02  01 00 02 01    .......c........
                0096: 00 30 11 30  0F 06 0A 2B  06 01 06 03  0F 01 01 04    .0.0...+........
                0112: 00 41 01 01                                           .A..";

            var messageBytes = Dump.BytesFromHexString(dump);

            var reader = new AsnReader(messageBytes, AsnEncodingRules.BER);

            var message = SnmpV3Message.ReadFrom(reader);

            Assert.NotNull(message);

            Assert.Equal(
                ProtocolVersion.SnmpV3,
                message.ProtocolVersion);

            Assert.Equal(MsgFlags.NoAuthNoPriv, message.GlobalData.MsgFlags);

            var usmSecParams = message.SecurityParameters;

            Assert.NotNull(usmSecParams);

            Assert.Equal(SecurityModel.Usm, message.GlobalData.MsgSecurityModel);

            Assert.NotEmpty(usmSecParams.EngineId.ToArray());

            Assert.Equal(1, usmSecParams.EngineBoots);

            Assert.True(usmSecParams.EngineId.Length == 17);
        }
    }
}
