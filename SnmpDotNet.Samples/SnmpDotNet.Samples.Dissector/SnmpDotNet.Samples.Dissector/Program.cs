using SnmpDotNet.Asn1;
using SnmpDotNet.Utils;
using System.Diagnostics;

var dump = @"Received 167 byte packet from UDP: [127.0.0.1]:161->[0.0.0.0]:35616
0000: 30 81 A4 02  01 03 30 10  02 04 0A 13  C6 5C 02 02    0.....0......\..
0016: 05 C0 04 01  01 02 01 03  04 3E 30 3C  04 17 80 00    .........>0<....
0032: 1F 88 04 38  30 30 30 30  30 30 32 30  31 30 39 38    ...8000000201098
0048: 34 30 33 30  31 02 01 19  02 02 3F F1  04 0A 75 73    40301.....?...us
0064: 72 5F 76 33  5F 4D 44 35  04 0C 12 ED  58 14 03 6E    r_v3_MD5....X..n
0080: BE FC C8 C0  D0 EB 04 00  30 4D 04 17  80 00 1F 88    ........0M......
0096: 04 38 30 30  30 30 30 30  32 30 31 30  39 38 34 30    .800000020109840
0112: 33 30 31 04  00 A2 30 02  04 13 7D 89  6D 02 01 00    301...0...}.m...
0128: 02 01 00 30  22 30 20 06  08 2B 06 01  02 01 01 01    ...0""0 ..+......
0144: 00 04 14 4E  65 74 53 6E  6D 70 54 65  73 74 43 6F    ...NetSnmpTestCo
0160: 6E 74 61 69  6E 65 72                                 ntainer";

Console.CursorVisible = false;

var bytes = Dump.BytesFromHexString(dump);

var members = BERUtils.Dump(bytes);

var currMember = members[0];

foreach (var m in members)
{
    Console.WriteLine($"    {m}");
}

Console.WriteLine();
var hexDumpTop = Console.CursorTop + 1;
Console.WriteLine();

var cyan = $"\u001b[38;2;{0};{255};{255}m";
var black = $"\u001b[38;2;{0};{0};{0}m";
var reset = "\u001b[0m";
var magenta = $"\u001b[38;2;{215};{8};{204}m";
var arrow = cyan + "==>" + reset;

var clearLine = "\r" + Enumerable
    .Repeat(" ", Console.BufferWidth)
    .Aggregate((a, b) => a + b);

void PrintHexDump()
{
    var offset = 0;
    Console.WriteLine(clearLine);
    Console.CursorTop -= 1;
    Console.WriteLine(
        $"\r{cyan}offset: {currMember.Offset} length: {currMember.HeaderSize}+{currMember.ContentLen}{reset}");
    foreach (var row in bytes.Chunk(16))
    {
        var offsetStr = offset.ToString().PadLeft(4, '0');

        var bytesRow = Convert.ToHexString(row)
            .Chunk(2)
            .Select((x, idx) =>
            {
                var item = $"{x[0]}{x[1]}";
                var absoluteOffset = idx + offset;
                if (absoluteOffset >= currMember.Offset && absoluteOffset < currMember.OffsetEnd)
                {
                    if (absoluteOffset < currMember.Offset + currMember.HeaderSize)
                    {
                        item = magenta + item + reset;
                    }
                    else
                    {
                        item = cyan + item + reset;
                    }
                }
                return item;
            });

        var formatted = bytesRow
            .Chunk(4)
            .Select(x => string.Join(" ", x))
            .Aggregate((a, b) => a + "  " + b);

        Console.WriteLine(offsetStr + ": " + formatted);
        offset += 16;
    }
}

PrintHexDump();

Console.WriteLine();
var bgGray = $"{black}\u001b[47;1m";
Console.WriteLine($"{bgGray}^X{reset} Copy Highlighted Bytes");

Console.SetCursorPosition(0, 0);
Console.WriteLine(arrow);
Console.SetCursorPosition(0, 0);

while (true)
{
    if (Console.KeyAvailable)
    {
        var key = Console.ReadKey(true);

        switch (key.Key)
        {
            case ConsoleKey.UpArrow:
                if (Console.CursorTop > 0)
                {
                    currMember = members[Console.CursorTop];

                    Console.Write("\r    " + currMember);

                    Console.SetCursorPosition(0, Console.CursorTop - 1);

                    currMember = members[Console.CursorTop] with
                    {
                        TagColor = cyan
                    };
                    Console.Write($"{arrow} {currMember}");

                    var oldTop = Console.CursorTop;
                    Console.SetCursorPosition(0, hexDumpTop);
                    PrintHexDump();
                    Console.SetCursorPosition(0, oldTop);
                }
                break;
            case ConsoleKey.DownArrow:
                if (Console.CursorTop < members.Count - 1)
                {
                    currMember = members[Console.CursorTop];

                    Console.Write("\r    " + currMember);

                    Console.SetCursorPosition(0, Console.CursorTop + 1);

                    currMember = members[Console.CursorTop] with
                    {
                        TagColor = cyan
                    };
                    Console.Write($"{arrow} {currMember}");

                    var oldTop = Console.CursorTop;
                    Console.SetCursorPosition(0, hexDumpTop);
                    PrintHexDump();
                    Console.SetCursorPosition(0, oldTop);
                }
                break;
            case ConsoleKey.D6:
                if (key.Modifiers.HasFlag(ConsoleModifiers.Alt))
                {
                    var data = bytes[currMember.Offset..currMember.OffsetEnd];
                    Debug.WriteLine(Convert.ToHexString(data));
                }
                break;
        }
    }
    Console.CursorVisible = false;
    Thread.Sleep(20);
}