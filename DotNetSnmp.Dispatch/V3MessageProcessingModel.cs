using DotNetSnmp.Common.Definitions;
using DotNetSnmp.Protocol.V3;
using DotNetSnmp.Protocol.V3.Security;
using DotNetSnmp.Protocol.V3.Security.Authentication;
using DotNetSnmp.Protocol.V3.Security.Privacy;
using DotNetSnmp.Transport.Targets;
using DotNetSnmp.V3.Security.Privacy;
using System.Buffers;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace DotNetSnmp.Client
{
    public class V3MessageProcessingModel : IMessageProcessingModel
    {
        public bool IsProtocolVersionSupported(ProtocolVersion version)
        {
            return version == ProtocolVersion.SnmpV3;
        }

        public bool TryPrepareDataElements(
            in ReadOnlyMemory<byte> incomingMessage,
            out string securityName,
            out SecurityLevel securityLevel,
            out SecurityModel securityModel,
            out Pdu pdu,
            out int sendPduHandle,
            out MessageProcessingResult result)
        {
            throw new NotImplementedException();
        }

        private static IncrementalHash CreateHash(AuthenticationProtocol authProto) => authProto switch
        {
            AuthenticationProtocol.Md5 => IncrementalHash.CreateHash(HashAlgorithmName.MD5),
            AuthenticationProtocol.Sha1 => IncrementalHash.CreateHash(HashAlgorithmName.SHA1),
            AuthenticationProtocol.Sha256 => IncrementalHash.CreateHash(HashAlgorithmName.SHA256),
            AuthenticationProtocol.Sha384 => IncrementalHash.CreateHash(HashAlgorithmName.SHA384),
            AuthenticationProtocol.Sha512 => IncrementalHash.CreateHash(HashAlgorithmName.SHA512),
            AuthenticationProtocol.None => throw new ArgumentException(),
            _ => throw new ArgumentException()
        };

        public bool TryPrepareOutgoingMessage(
            ISnmpTarget target,
            Pdu pdu,
            in ReadOnlyMemory<byte> secEngineId,
            out int sendPduHandle, 
            out SnmpMessage outgoingMessage, 
            out MessageProcessingResult result, 
            bool expectResponse = true)
        {
            sendPduHandle = -1;
            outgoingMessage = null;
            result = MessageProcessingResult.Success;
            var securityLevel = target.SecurityLevel;

            if (target.SecurityModel != SecurityModel.Usm)
            {
                result = MessageProcessingResult.UnsupportedSecurityModel;
                return false;
            }

            if (pdu is ScopedPdu scopedPdu == false)
            {
                throw new ArgumentException(
                    $"{nameof(pdu)} must be ScopedPdu for V3MessageProcessingModel");
            }


            if (scopedPdu!.IsConfirmed() == false)
            {
                throw new ArgumentException("Processing outgoing responses is not supported!");
            }

            if (secEngineId.IsEmpty)
            {
                securityLevel = SecurityLevel.None;
                scopedPdu = (ScopedPdu) scopedPdu.Clone();
                scopedPdu.Pdu.RequestId = 0;
                scopedPdu.VariableBindings?.Clear();
            }

            if (pdu.RequestId <= 0)
            {
                pdu.RequestId = Random.Shared.Next();
            }

            var msgFlags = securityLevel switch
            {
                SecurityLevel.AuthOnly => MsgFlags.Auth,
                SecurityLevel.PrivOnly => MsgFlags.Priv,
                SecurityLevel.AuthAndPriv => MsgFlags.Auth | MsgFlags.Priv,
                SecurityLevel.None => MsgFlags.NoAuthNoPriv,
                _ => MsgFlags.NoAuthNoPriv
            };

            if (pdu.IsConfirmed())
            {
                msgFlags |= MsgFlags.Reportable;
            }

            var message = new SnmpV3Message
            {
                GlobalData = new()
                {
                    MsgId = 0, // TODO
                    MsgFlags = msgFlags,
                    MsgMaxSize = target.MaxMessageSize,
                    MsgSecurityModel = target.SecurityModel
                },
                SecurityParameters = new()
                {
                    SecurityName = target.SecurityName,
                    AuthenticationProtocol = target.AuthProtocol,
                    PrivacyProtocol = target.PrivProtocol
                },
                ScopedPdu = scopedPdu,
            };

            var writer = new AsnWriter(AsnEncodingRules.BER);

            message.WriteTo(writer);

            var encodedMessage = writer.Encode();

            if (msgFlags.HasFlag(MsgFlags.Priv)
                && target.PrivProtocol != PrivacyProtocol.None)
            {
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.MD5);

                var privKey = new byte[hash.HashLengthInBytes];

                KeyUtils.GenerateLocalizedKey(
                    target.UserPasswordBytes,
                    secEngineId,
                    hash,
                    privKey
                );

                IPrivacyService privModel = target.PrivProtocol switch
                {
                    PrivacyProtocol.Des => new DESPrivacyService(privKey, 0), // TODO
                    PrivacyProtocol.Aes => new AESPrivacyService(privKey, 0, 0), // TODO
                    PrivacyProtocol.None => throw new ArgumentException(),
                    _ => throw new ArgumentException()
                };

                writer.Reset();
                scopedPdu.WriteTo(writer);
                var encodedScopedPdu = writer.Encode();

                var buff = ArrayPool<byte>.Shared.Rent(ushort.MaxValue);
                var encryptedPdu = buff.AsSpan();
                var privParam = new byte[privModel.PrivacyParametersLength];

                var size = privModel.EncryptScopedPdu(encodedScopedPdu, privParam, encryptedPdu);

                message.ScopedPdu = null;
                var encryptedScopedPdu = new byte[size];
                encryptedPdu[..size].CopyTo(encryptedScopedPdu);
                message.EncryptedScopedPdu = encryptedScopedPdu;
            }
            
            if (msgFlags.HasFlag(MsgFlags.Auth)
                && target.AuthProtocol != AuthenticationProtocol.None)
            {
                using var hash = CreateHash(target.AuthProtocol);

                var authKey = new byte[hash.HashLengthInBytes];

                KeyUtils.GenerateLocalizedKey(
                    target.UserPasswordBytes,
                    secEngineId,
                    hash,
                    authKey
                );

                var authModel = new AuthenticationService(target.AuthProtocol, authKey);

                var authParamsLen = authModel.TruncatedDigestSize;

                var authParams = new byte[authParamsLen];

                _ = authModel.AuthenticateOutgoingMsg(encodedMessage, authParams);

                message.SecurityParameters.AuthParams = authParams;

            }



            outgoingMessage = message;

            return true;
        }
    }
}
