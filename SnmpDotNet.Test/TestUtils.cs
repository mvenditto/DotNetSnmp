using SnmpDotNet.Protocol.V3.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SnmpDotNet.Test
{
    internal static class TestUtils
    {
        internal const string TestPassword = "Password1";

        internal const string EngineIdBase64 = "gAAfiAQ4MDAwMDAwMjAxMDk4NDAzMDE=";

        internal static byte[] GetAuthKey(byte[] engineId, HashAlgorithmName? hashAlgorithm = null)
        {
            var hash_ = hashAlgorithm ?? HashAlgorithmName.MD5;

            using var hash = IncrementalHash.CreateHash(hash_);

            var authKey = new byte[hash.HashLengthInBytes];

            KeyUtils.GenerateLocalizedKey(
                TestPassword.GetBytesMemoryOrDefault(Encoding.UTF8),
                engineId,
                hash,
                authKey
            );

            return authKey; ;
        }
    }
}
