using SnmpDotNet.Asn1.Serialization;
using SnmpDotNet.Asn1.SyntaxObjects;
using System.Formats.Asn1;

namespace SnmpDotNet.Common.Definitions
{
    public abstract class Pdu : IAsnSerializable
    {
        public abstract Asn1Tag PduType { get; }

        public int RequestId { get; set; } = 0;

        public PduErrorStatus ErrorStatus { get; set; } = 0;

        public int ErrorIndex { get; set; } = 0;

        public VarBindList VariableBindings { get; set; }

        public bool HasData => VariableBindings?.IsEmpty == false;

        public abstract void WriteTo(AsnWriter writer);

        /// <summary>
        /// Throws an exception if the ErrorStatus property for the SNMP response PDU is != 0.
        /// </summary>
        /// <see cref="PduErrorStatus"/>
        /// <exception cref="SnmpRequestException"></exception>
        public void EnsureNoError()
        {
            if (ErrorStatus != PduErrorStatus.NoError)
            {
                throw new SnmpRequestException(ErrorStatus, ErrorIndex);
            }
        }
    }
}
