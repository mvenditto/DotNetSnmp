using DotNetSnmp.Asn1.SyntaxObjects;
using DotNetSnmp.Protocol.V1;
using DotNetSnmp.Protocol.V3;
using DotNetSnmp.Protocol.V3.Security.Privacy;
using DotNetSnmp.Utils;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using Xunit;

namespace DotNetSnmp.Test
{
    [ExcludeFromCodeCoverage]
    public class PrivacyTest
    {
        [Fact]
        public void DecryptEncryptPdu_DES()
        {
            var reportDump = @"Received 127 byte packet from UDP: [127.0.0.1]:161->[0.0.0.0]:58621
                0000: 30 7D 02 01  03 30 10 02  04 1C 66 FC  E3 02 02 05    0}...0....f.....
                0016: C0 04 01 00  02 01 03 04  28 30 26 04  17 80 00 1F    ........(0&.....
                0032: 88 04 38 30  30 30 30 30  30 32 30 31  30 39 38 34    ..80000002010984
                0048: 30 33 30 31  02 01 18 02  02 03 34 04  00 04 00 04    0301......4.....
                0064: 00 30 3C 04  17 80 00 1F  88 04 38 30  30 30 30 30    .0<.......800000
                0080: 30 32 30 31  30 39 38 34  30 33 30 31  04 00 A8 1F    020109840301....
                0096: 02 04 7F A3  0A 43 02 01  00 02 01 00  30 11 30 0F    .....C......0.0.
                0112: 06 0A 2B 06  01 06 03 0F  01 01 04 00  41 01 05       ..+.........A..";

            var reportBytes = Dump.BytesFromHexString(reportDump);

            var privParameters = Convert.FromHexString("00000018223C8AAB");

            var encryptedPdu = Convert.FromHexString(
                "0450A90E09A909ED45C224B75D67B1CAA5B6EBBEA93AA75F110A8BAD110227246DD613CA5216A7E8FDDC2089092FF202BB4500A839DEADEA432326E77007B08907D9F6E5E551E22891CD291CFBB5AACC5099"
            );

            var key = TestUtils.GetAuthKey(
                Convert.FromBase64String(TestUtils.EngineIdBase64),
                HashAlgorithmName.MD5
             );

            var report = SnmpV3Message.ReadFrom(
                new AsnReader(reportBytes, AsnEncodingRules.BER));

            var desPrivacy = new DESPrivacyService(
                key, 
                report.SecurityParameters.EngineBoots);

            var scopedPduOctets = encryptedPdu[2..]; // skip the BER 'headers', only get the encrypted octets

            var rawDecryptedPdu = desPrivacy.DecryptScopedPdu(
                scopedPduOctets, 
                privParameters);

            var decryptedPdu = ScopedPdu.ReadFrom(
                new AsnReader(rawDecryptedPdu, AsnEncodingRules.BER));

            Assert.IsType<GetResponsePdu>(decryptedPdu.Pdu);

            var varBindList = decryptedPdu.Pdu.VariableBindings;

            Assert.NotNull(varBindList);

            Assert.True(varBindList!.Any());

            var vb = varBindList!.First();

            Assert.True(vb.Value is OctetString);

            var tt = vb.Value.ToString();

            Assert.Equal("String: NetSnmpTestContainer", tt);
        }

        /*
        [Fact]
        public void TestWalk()
        {
            var walkDump = @".\authPriv_MD5_DES_walk.txt";

            var dump = File.ReadAllText(walkDump);

            var messages = dump.Split("\n\n");

            var reportDump = messages[0];

            var reportResponse = messages[1];

            var responses = messages[2..]
                .Select(m => m.Trim())
                .Where(m => m.StartsWith("Received"));

            var reportBytes = Dump.BytesFromHexString(reportResponse);

            var key = TestUtils.GetAuthKey(
                Convert.FromBase64String(TestUtils.EngineIdBase64),
                HashAlgorithmName.MD5
             );

            var report = SnmpV3Message.ReadFrom(
                new AsnReader(reportBytes, AsnEncodingRules.BER));

            var desPrivacy = new DESPrivacyService(
                key,
                report.SecurityParameters.EngineBoots);

            foreach(var responseDump in responses)
            {
                var responseBytes = Dump.BytesFromHexString(responseDump);
                
                var msg = SnmpV3Message.ReadFrom(
                    new AsnReader(responseBytes, AsnEncodingRules.BER));

                var encryptedPdu = msg.EncryptedScopedPdu;

                var rawDecryptedPdu = desPrivacy.DecryptScopedPdu(
                    encryptedPdu,
                    msg.SecurityParameters.PrivParams);

                var pdu = ScopedPdu.ReadFrom(
                    new AsnReader(rawDecryptedPdu, AsnEncodingRules.BER));
                
            }
        }
        */

        [Fact]
        public void DecryptEncryptPdu_AES()
        {
            var reportDump = @"Received 126 byte packet from UDP: [127.0.0.1]:161->[0.0.0.0]:50990
            0000: 30 7C 02 01  03 30 10 02  04 2C F1 44  4F 02 02 05    0|...0...,.DO...
            0016: C0 04 01 00  02 01 03 04  27 30 25 04  17 80 00 1F    ........'0%.....
            0032: 88 04 38 30  30 30 30 30  30 32 30 31  30 39 38 34    ..80000002010984
            0048: 30 33 30 31  02 01 18 02  01 2B 04 00  04 00 04 00    0301.....+......
            0064: 30 3C 04 17  80 00 1F 88  04 38 30 30  30 30 30 30    0<.......8000000
            0080: 32 30 31 30  39 38 34 30  33 30 31 04  00 A8 1F 02    20109840301.....
            0096: 04 2D 67 AA  3C 02 01 00  02 01 00 30  11 30 0F 06    .-g.<......0.0..
            0112: 0A 2B 06 01  06 03 0F 01  01 04 00 41  01 02          .+.........A..";

            var reportBytes = Dump.BytesFromHexString(reportDump);

            var privParameters = Convert.FromHexString("7D20E4A4FD39F2B8");

            var encryptedPdu = Convert.FromHexString(
                "044FD713175252F08935E2EDF36D57810BBB2996CF89AB32C3CBC21F1AE9E5F93232396C1DC22C96F7850484CF94A33830E7494735883C1EEE840A2FEAA756C9D8F8355CD25326953151E5ACC3C28A2148"
            );

            var key = TestUtils.GetAuthKey(
                Convert.FromBase64String(TestUtils.EngineIdBase64),
                HashAlgorithmName.MD5
             );

            var report = SnmpV3Message.ReadFrom(
                new AsnReader(reportBytes, AsnEncodingRules.BER));

            var aesPrivacy = new AESPrivacyService(
                key,
                report.SecurityParameters.EngineBoots,
                report.SecurityParameters.EngineTime);

            var scopedPduOctets = encryptedPdu[2..]; // skip the BER 'headers', only get the encrypted octets

            var rawDecryptedPdu = aesPrivacy.DecryptScopedPdu(
                scopedPduOctets,
                privParameters);

            var decryptedPdu = ScopedPdu.ReadFrom(
                new AsnReader(rawDecryptedPdu, AsnEncodingRules.BER));

            Assert.IsType<GetResponsePdu>(decryptedPdu.Pdu);

            var varBindList = decryptedPdu.Pdu.VariableBindings;

            Assert.NotNull(varBindList);

            Assert.True(varBindList!.Any());

            var vb = varBindList!.First();

            Assert.True(vb.Value is OctetString);

            var tt = vb.Value.ToString();

            Assert.Equal("String: NetSnmpTestContainer", tt);
        }
    }
}
