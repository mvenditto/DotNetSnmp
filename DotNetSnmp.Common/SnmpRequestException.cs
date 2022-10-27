using DotNetSnmp.Common.Definitions;

namespace DotNetSnmp.Common
{
    public class SnmpRequestException : Exception
    {
        public SnmpRequestException(PduErrorStatus err, int errIdx)
            :base($"The Agent responded with error {err}({(byte) err}) at index {errIdx}")
        {
            
        }
    }
}
