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

        /// <summary>
        /// Get the recommended hash algorithm according to RFC6637 - 13. Security Considerations
        /// </summary>
        /// <param name="oid">The curve object identifier.</param>
        /// <returns>The hash algorithm tag (default is SHA 512).</returns>
        public static HashAlgorithmTag HashAlgoritmByCurveOid(DerObjectIdentifier oid)
        {
            HashAlgorithmTag hashAlgo = HashAlgorithmTag.Sha512;

            if (oid.On(Asn1.X9.X9ObjectIdentifiers.PrimeCurve))
                hashAlgo = HashAlgorithmTag.Sha256;
            else if (oid == Asn1.Sec.SecObjectIdentifiers.SecP384r1)
                hashAlgo = HashAlgorithmTag.Sha384;

            return hashAlgo;
        }

        /// <summary>
        /// Get the recommended symmetric key algorithm according to RFC6637 - 13. Security Considerations
        /// </summary>
        /// <param name="oid">The curve object identifier.</param>
        /// <returns>The symmetric key algorithm tag  (default is AES 256).</returns>
        public static SymmetricKeyAlgorithmTag SymmetricKeyAlgorithmByCurveOid(DerObjectIdentifier oid)
        {
            SymmetricKeyAlgorithmTag symmAlgo = SymmetricKeyAlgorithmTag.Aes256;

            if (oid.On(Asn1.X9.X9ObjectIdentifiers.PrimeCurve))
                symmAlgo = SymmetricKeyAlgorithmTag.Aes128;
            else if (oid == Asn1.Sec.SecObjectIdentifiers.SecP384r1)
                symmAlgo = SymmetricKeyAlgorithmTag.Aes192;
            return symmAlgo;
        }

        public EcdhPublicBcpgKey(
            DerObjectIdentifier oid,
            ECPoint point,
            HashAlgorithmTag hashAlgorithm = HashAlgorithmTag.Sha512,
            SymmetricKeyAlgorithmTag symmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Aes256) : base(oid, point)
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
