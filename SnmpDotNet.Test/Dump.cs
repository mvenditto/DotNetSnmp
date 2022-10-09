﻿using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

namespace SnmpDotNet.Test
{
    [ExcludeFromCodeCoverage]
    internal static class Dump
    {
        /*
            Sending 43 bytes to UDP: [127.0.0.1]:161->[0.0.0.0]:0
            0000: 30 29 02 01  00 04 06 70  75 62 6C 69  63 A0 1C 02    0).....public...
            0016: 04 0C BB 47  10 02 01 00  02 01 00 30  0E 30 0C 06    ...G.......0.0..
            0032: 08 2B 06 01  02 01 01 01  00 05 00                    .+.........
        */

        private static readonly Regex _headerRegex = new (@"^(?:Received|Sending) (?<bytes>\d+) (?:.*) (:?from|to)");

        public static byte[] BytesFromHexString(string textualDump)
        {
            var lines = Regex.Split(textualDump, @"\r*\n")
                .Select(x => x.Trim())
                .ToList();

            var headerLine = lines.First();

            var hexData = lines
                .Skip(1)
                .SelectMany(l => l.Split().Skip(1).SkipLast(1).Where(x => !string.IsNullOrEmpty(x)))
                .Select(b => Convert.ToByte(b, 16))
                .ToArray();

            var m = _headerRegex.Match(headerLine);

            var bytes = int.Parse(m.Groups["bytes"].Value);

            if (bytes != hexData.Length)
            {
                throw new Exception("Dump parse error");
            }

            return hexData;
        }
    }
}
