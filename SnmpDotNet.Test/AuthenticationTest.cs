using SnmpDotNet.Common.Definitions;
using SnmpDotNet.Protocol.V3;
using SnmpDotNet.Protocol.V3.Security;
using SnmpDotNet.Protocol.V3.Security.Authentication;
using SnmpDotNet.Test.Helpers.XUnit.Project.Attributes;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace SnmpDotNet.Test
{
    [TestCaseOrderer("XUnit.Project.Orderers.PriorityOrderer", "XUnit.Project")]
    public class AuthenticationTest
    {
        private const string TestPassword = "Password1";

        private const string EngineIdBase64 = "gAAfiAQ4MDAwMDAwMjAxMDk4NDAzMDE=";

        private byte[] _engineId;

        private static byte[] GetAuthKey(byte[] engineId)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.MD5);

            var authKey = new byte[hash.HashLengthInBytes];

            KeyUtils.GenerateLocalizedKey(
                TestPassword.GetBytesMemoryOrDefault(Encoding.UTF8),
                engineId,
                hash,
                authKey
            );

            return authKey; ;
        }

        [Fact, TestPriority(0)]
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

        [Fact, TestPriority(1)]
        public void EncodeDecodeReportResponseMessage()
        {
            var dump = @"Received 127 byte packet from UDP: [127.0.0.1]:161->[0.0.0.0]:57524
                0000: 30 7D 02 01  03 30 11 02  04 51 06 5D  16 02 03 00    0}...0...Q.]....
                0016: FF E3 04 01  00 02 01 03  04 27 30 25  04 17 80 00    .........'0%....
                0032: 1F 88 04 38  30 30 30 30  30 30 32 30  31 30 39 38    ...8000000201098
                0048: 34 30 33 30  31 02 01 01  02 01 17 04  00 04 00 04    40301...........
                0064: 00 30 3C 04  17 80 00 1F  88 04 38 30  30 30 30 30    .0<.......800000
                0080: 30 32 30 31  30 39 38 34  30 33 30 31  04 00 A8 1F    020109840301....
                0096: 02 04 4E ED  B6 35 02 01  00 02 01 00  30 11 30 0F    ..N..5......0.0.
                0112: 06 0A 2B 06  01 06 03 0F  01 01 04 00  41 01 01       ..+.........A..";

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

            _engineId = usmSecParams.EngineId.ToArray();

            Assert.NotEmpty(_engineId);

            Assert.Equal(_engineId, Convert.FromBase64String(EngineIdBase64));

            Assert.Equal(1, usmSecParams.EngineBoots);

            Assert.True(usmSecParams.EngineId.Span.SequenceEqual(
                Convert.FromBase64String(EngineIdBase64)));
        }

        [Fact, TestPriority(2)]
        public async void EncodeDecodeGetRequest_AuthNoPriv_MD5()
        {
            var dump = @"Sending 146 bytes to UDP: [127.0.0.1]:161->[0.0.0.0]:0
                0000: 30 81 8F 02  01 03 30 10  02 04 51 06  5D 15 02 02    0.....0...Q.]...
                0016: 05 C0 04 01  05 02 01 03  04 3D 30 3B  04 17 80 00    .........=0;....
                0032: 1F 88 04 38  30 30 30 30  30 30 32 30  31 30 39 38    ...8000000201098
                0048: 34 30 33 30  31 02 01 01  02 01 17 04  0A 75 73 72    40301........usr
                0064: 5F 76 33 5F  4D 44 35 04  0C 44 4F CF  E5 51 A7 EF    _v3_MD5..DO..Q..
                0080: 91 3E FB A3  AD 04 00 30  39 04 17 80  00 1F 88 04    .>.....09.......
                0096: 38 30 30 30  30 30 30 32  30 31 30 39  38 34 30 33    8000000201098403
                0112: 30 31 04 00  A0 1C 02 04  4E ED B6 34  02 01 00 02    01......N..4....
                0128: 01 00 30 0E  30 0C 06 08  2B 06 01 02  01 01 03 00    ..0.0...+.......
                0144: 05 00                                                 ..";

            var messageBytes = Dump.BytesFromHexString(dump);

            var reader = new AsnReader(messageBytes, AsnEncodingRules.BER);

            var message = SnmpV3Message.ReadFrom(reader);

            Assert.NotNull(message);

            Assert.Equal(
                ProtocolVersion.SnmpV3,
                message.ProtocolVersion);

            Assert.True(message.GlobalData.MsgFlags.HasFlag(MsgFlags.Auth));

            Assert.False(message.GlobalData.MsgFlags.HasFlag(MsgFlags.Priv));

            var usmSecParams = message.SecurityParameters;

            Assert.NotNull(usmSecParams);

            _engineId = usmSecParams.EngineId.ToArray();

            Assert.NotEmpty(_engineId);

            Assert.Equal(_engineId, Convert.FromBase64String(EngineIdBase64));

            Assert.Equal(12, message.SecurityParameters.AuthParams.Length);

            var authParams = new byte[12];
            var calculatedAuthParams = new byte[12];

            message.SecurityParameters.AuthParams.CopyTo(authParams);

            message.SecurityParameters.AuthParams.Span.Fill(0x0);

            var writer = new AsnWriter(AsnEncodingRules.BER);
            message.WriteTo(writer);
            var encoded = writer.Encode();

            var md5Auth = new AuthenticationService(
                AuthenticationProtocol.Md5, 
                GetAuthKey(_engineId));

            await md5Auth.AuthenticateOutgoingMsg(encoded, calculatedAuthParams);

            Assert.True(calculatedAuthParams.SequenceEqual(authParams));
        }
    }
}
