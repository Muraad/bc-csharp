using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Org.BouncyCastle.Bcpg
{
    /**
     * base class for an ECDH Public Key.
     */
    public class EcdhPublicBcpgKey : EcPublicBcpgKey
    {
        private byte reserved;
        private byte hashFunctionId;
        private byte symAlgorithmId;

        /**
         * @param in the stream to read the packet from.
         */
        public EcdhPublicBcpgKey(
            BcpgInputStream bcpgIn) : base(bcpgIn)
        {

            int length = bcpgIn.ReadByte();
            byte[] kdfParameters =  new byte[length];
            if (kdfParameters.Length != 3)
            {
                throw new ArgumentException("kdf parameters size of 3 expected.");
            }

            bcpgIn.ReadFully(kdfParameters);

            reserved = kdfParameters[0];
            hashFunctionId = kdfParameters[1];
            symAlgorithmId = kdfParameters[2];

            verifyHashAlgorithm();
            verifySymmetricKeyAlgorithm();
        }

        public EcdhPublicBcpgKey(
            DerObjectIdentifier oid,
            ECPoint point,
            HashAlgorithmTag hashAlgorithm,
            SymmetricKeyAlgorithmTag symmetricKeyAlgorithm) : base(oid, point)
        {

            reserved = 1;
            hashFunctionId = (byte)hashAlgorithm;
            symAlgorithmId = (byte)symmetricKeyAlgorithm;

            verifyHashAlgorithm();
            verifySymmetricKeyAlgorithm();
        }

        public byte Reserved { get { return reserved; } }

        public byte HashAlgorithm { get { return hashFunctionId; } }

        public byte SymmetricKeyAlgorithm { get { return symAlgorithmId; } }

        public override void Encode(
            BcpgOutputStream bcpgOut)
        {
            base.Encode(bcpgOut);
            bcpgOut.Write(0x3);
            bcpgOut.Write(reserved);
            bcpgOut.Write(hashFunctionId);
            bcpgOut.Write(symAlgorithmId);
        }

        private void verifyHashAlgorithm()
        {
            
            switch ((HashAlgorithmTag)hashFunctionId)
            {
            case HashAlgorithmTag.Sha256:
            case HashAlgorithmTag.Sha384:
            case HashAlgorithmTag.Sha512:
                break;

            default:
                throw new ArgumentException("Hash algorithm must be SHA-256 or stronger.");
            }
        }

        private void verifySymmetricKeyAlgorithm()
        {
            switch ((SymmetricKeyAlgorithmTag)symAlgorithmId)
            {
            case SymmetricKeyAlgorithmTag.Aes128:
            case SymmetricKeyAlgorithmTag.Aes192:
            case SymmetricKeyAlgorithmTag.Aes256:
                break;

            default:
                throw new ArgumentException("Symmetric key algorithm must be AES-128 or stronger.");
            }
        }
    }
}
