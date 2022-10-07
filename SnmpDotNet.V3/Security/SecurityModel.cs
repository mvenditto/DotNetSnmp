using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SnmpDotNet.Protocol.V3.Security
{
    public enum SecurityModel: byte
    {
        V1 = 0,
        V2c = 1,
        Usm = 3
    }
}
