using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class RFC6637KDFCalculator
    {
        // "Anonymous Sender    ", which is the octet sequence
        private static readonly byte[] ANONYMOUS_SENDER = Hex.Decode("416E6F6E796D6F75732053656E64657220202020");
        
        private IDigest digCalc;
        private int keyAlgorithm;

        public RFC6637KDFCalculator(IDigest digCalc, int keyAlgorithm)
        {
            this.digCalc = digCalc;
            this.keyAlgorithm = keyAlgorithm;
        }

        public byte[] CreateKey(DerObjectIdentifier curveOID,  ECPoint s, byte[] recipientFingerPrint)
        {
            try
            {
                // RFC 6637 - Section 8
                // curve_OID_len = (byte)len(curve_OID);
                // Param = curve_OID_len || curve_OID || public_key_alg_ID || 03
                // || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap || "Anonymous
                // Sender    " || recipient_fingerprint;
                // Z_len = the key size for the KEK_alg_ID used with AESKeyWrap
                // Compute Z = KDF( S, Z_len, Param );
                MemoryStream pOut = new MemoryStream();

                byte[] encOid = curveOID.GetEncoded();

                pOut.Write(encOid, 1, encOid.Length - 1);
                pOut.WriteByte((byte)PublicKeyAlgorithmTag.EC);
                pOut.WriteByte(0x03);
                pOut.WriteByte(0x01);
                //Org.BouncyCastle.Security.DigestUtilities.GetObjectIdentifier(digCalc.AlgorithmName).Encode(pOut);
                pOut.WriteByte((byte)keyAlgorithm);
                pOut.Write(ANONYMOUS_SENDER, 0, ANONYMOUS_SENDER.Length);
                pOut.Write(recipientFingerPrint, 0, recipientFingerPrint.Length);

                return KDF(digCalc, s, getKeyLen(keyAlgorithm), pOut.ToArray());
            }
            catch (IOException e)
            {
                throw new PgpException("Exception performing KDF: " + e.Message, e);
            }
        }

        // RFC 6637 - Section 7
        //   Implements KDF( X, oBits, Param );
        //   Input: point X = (x,y)
        //   oBits - the desired size of output
        //   hBits - the size of output of hash function Hash
        //   Param - octets representing the parameters
        //   Assumes that oBits <= hBits
        //   Convert the point X to the octet string, see section 6:
        //   ZB' = 04 || x || y
        //   and extract the x portion from ZB'
        //         ZB = x;
        //         MB = Hash ( 00 || 00 || 00 || 01 || ZB || Param );
        //   return oBits leftmost bits of MB.
        private static byte[] KDF(IDigest digCalc, ECPoint s, int keyLen, byte[] param)
        {
            byte[] ZB = s.XCoord.GetEncoded();

            digCalc.Update(0x00);
            digCalc.Update(0x00);
            digCalc.Update(0x00);
            digCalc.Update(0x01);
            digCalc.Update(0x01);
            digCalc.BlockUpdate(ZB, 0, ZB.Length);
            digCalc.BlockUpdate(param, 0, param.Length);

            byte[] digest = new byte[digCalc.GetDigestSize()];
            digCalc.DoFinal(digest, 0);

            byte[] key = new byte[keyLen];

            Array.Copy(digest, 0, key, 0, key.Length);

            return key;
        }

        private static int getKeyLen(int algID)
        {
            switch ((SymmetricKeyAlgorithmTag) algID)
            {
            case SymmetricKeyAlgorithmTag.Aes128:
                return 16;
            case SymmetricKeyAlgorithmTag.Aes192:
                return 24;
            case SymmetricKeyAlgorithmTag.Aes256:
                return 32;
            default:
                throw new PgpException("unknown symmetric algorithm ID: " + algID);
            }
        }
    }
}
