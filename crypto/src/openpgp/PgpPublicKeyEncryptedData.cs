using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto.EC;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>A public key encrypted data object.</remarks>
    public class PgpPublicKeyEncryptedData
        : PgpEncryptedData
    {
        private PublicKeyEncSessionPacket keyData;

		internal PgpPublicKeyEncryptedData(
            PublicKeyEncSessionPacket	keyData,
            InputStreamPacket			encData)
            : base(encData)
        {
            this.keyData = keyData;
        }

		private static IBufferedCipher GetKeyCipher(
            PublicKeyAlgorithmTag algorithm)
        {
            try
            {
                switch (algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                        return CipherUtilities.GetCipher("RSA//PKCS1Padding");
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        return CipherUtilities.GetCipher("ElGamal/ECB/PKCS1Padding");
                    default:
                        throw new PgpException("unknown asymmetric algorithm: " + algorithm);
                }
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }

		private bool ConfirmCheckSum(
            byte[] sessionInfo)
        {
            int check = 0;

			for (int i = 1; i != sessionInfo.Length - 2; i++)
            {
                check += sessionInfo[i] & 0xff;
            }

			return (sessionInfo[sessionInfo.Length - 2] == (byte)(check >> 8))
                && (sessionInfo[sessionInfo.Length - 1] == (byte)(check));
        }

		/// <summary>The key ID for the key used to encrypt the data.</summary>
        public long KeyId
        {
			get { return keyData.KeyId; }
        }

		/// <summary>
		/// Return the algorithm code for the symmetric algorithm used to encrypt the data.
		/// </summary>
		public SymmetricKeyAlgorithmTag GetSymmetricAlgorithm(
			PgpPrivateKey privKey)
		{
			byte[] plain = FetchSymmetricKeyData(privKey);

			return (SymmetricKeyAlgorithmTag) plain[0];
		}

		/// <summary>Return the decrypted data stream for the packet.</summary>
        public Stream GetDataStream(PgpPrivateKey privKey, HashAlgorithmTag validityDigest = HashAlgorithmTag.Sha1)
        {
            byte[] plain = null;
            if (keyData.Algorithm == PublicKeyAlgorithmTag.ECDH)
                plain = DecryptSessionData(privKey);
			else 
                plain = FetchSymmetricKeyData(privKey);

			IBufferedCipher c2;
			string cipherName = PgpUtilities.GetSymmetricCipherName((SymmetricKeyAlgorithmTag) plain[0]);
			string cName = cipherName;

			try
            {
                if (encData is SymmetricEncIntegrityPacket)
                {
					cName += "/CFB/NoPadding";
                }
                else
                {
					cName += "/OpenPGPCFB/NoPadding";
                }

				c2 = CipherUtilities.GetCipher(cName);
			}
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("exception creating cipher", e);
            }

			if (c2 == null)
				return encData.GetInputStream();

			try
            {
				KeyParameter key = ParameterUtilities.CreateKeyParameter(
					cipherName, plain, 1, plain.Length - 3);

				byte[] iv = new byte[c2.GetBlockSize()];

				c2.Init(false, new ParametersWithIV(key, iv));

                encStream = BcpgInputStream.Wrap(new CipherStream(encData.GetInputStream(), c2, null));

				if (encData is SymmetricEncIntegrityPacket)
                {
                    truncStream = new TruncatedStream(encStream);

                    if (validityDigest == HashAlgorithmTag.None)
                        validityDigest = HashAlgorithmTag.Sha1;         // Must be at least Sha1. None is not allowed here!!

					string digestName = PgpUtilities.GetDigestName(validityDigest);
					IDigest digest = DigestUtilities.GetDigest(digestName);

					encStream = new DigestStream(truncStream, digest, null);
                }

				if (Streams.ReadFully(encStream, iv, 0, iv.Length) < iv.Length)
					throw new EndOfStreamException("unexpected end of stream.");

				int v1 = encStream.ReadByte();
                int v2 = encStream.ReadByte();

				if (v1 < 0 || v2 < 0)
                    throw new EndOfStreamException("unexpected end of stream.");

				// Note: the oracle attack on the "quick check" bytes is deemed
				// a security risk for typical public key encryption usages,
				// therefore we do not perform the check.

//				bool repeatCheckPassed =
//					iv[iv.Length - 2] == (byte)v1
//					&&	iv[iv.Length - 1] == (byte)v2;
//
//				// Note: some versions of PGP appear to produce 0 for the extra
//				// bytes rather than repeating the two previous bytes
//				bool zeroesCheckPassed =
//					v1 == 0
//					&&	v2 == 0;
//
//				if (!repeatCheckPassed && !zeroesCheckPassed)
//				{
//					throw new PgpDataValidationException("quick check failed.");
//				}

				return encStream;
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception starting decryption", e);
            }
		}

        private byte[] getFingerprint(PublicKeyPacket publicPk)
        {
            IBcpgKey key = publicPk.Key;
            byte[] fingerprint = null;

            if (publicPk.Version <= 3)
            {
                RsaPublicBcpgKey rK = (RsaPublicBcpgKey)key;

                try
                {
                    IDigest digest = DigestUtilities.GetDigest("MD5");

                    byte[] bytes = rK.Modulus.ToByteArrayUnsigned();
                    digest.BlockUpdate(bytes, 0, bytes.Length);

                    bytes = rK.PublicExponent.ToByteArrayUnsigned();
                    digest.BlockUpdate(bytes, 0, bytes.Length);

                    fingerprint = DigestUtilities.DoFinal(digest);
                }
                //catch (NoSuchAlgorithmException)
                catch (Exception e)
                {
                    throw new IOException("can't find MD5", e);
                }
            }
            else
            {
                byte[] kBytes = publicPk.GetEncodedContents();

                try
                {
                    IDigest digest = DigestUtilities.GetDigest("SHA1");

                    digest.Update(0x99);
                    digest.Update((byte)(kBytes.Length >> 8));
                    digest.Update((byte)kBytes.Length);
                    digest.BlockUpdate(kBytes, 0, kBytes.Length);
                    fingerprint = DigestUtilities.DoFinal(digest);
                }
                catch (Exception e)
                {
                    throw new IOException("can't find SHA1", e);
                }
            }
            return fingerprint;
        }

        private byte[] DecryptSessionData(PgpPrivateKey privateKey)
        {
            ECPrivateKeyParameters keyParams = (ECPrivateKeyParameters)privateKey.Key;

            ECDHPublicBcpgKey ecKey = (ECDHPublicBcpgKey)privateKey.PublicKeyPacket.Key;
            X9ECParameters x9Params = ECNamedCurveTable.GetByOid(ecKey.CurveOid);
            if (x9Params == null)
                x9Params = CustomNamedCurves.GetByOid(ecKey.CurveOid);

            ECDomainParameters ecParams = new ECDomainParameters(x9Params.Curve, x9Params.G, x9Params.N);

            byte[] enc = keyData.GetEncSessionKey()[0].ToByteArrayUnsigned();

            int pLen = ((((enc[0] & 0xff) << 8) + (enc[1] & 0xff)) + 7) / 8;
            byte[] pEnc = new byte[pLen];

            Array.Copy(enc, 2, pEnc, 0, pLen);

            byte[] keyEnc = new byte[enc[pLen + 2]];

            Array.Copy(enc, 2 + pLen + 1, keyEnc, 0, keyEnc.Length);

            IWrapper c = WrapperUtilities.GetWrapper(PgpUtilities.GetSymmetricCipherName((SymmetricKeyAlgorithmTag)ecKey.SymmetricKeyAlgorithm) + "WRAP");

            ECPoint S = x9Params.Curve.DecodePoint(pEnc).Multiply(keyParams.D).Normalize();

            IDigest digest = DigestUtilities.GetDigest(PgpUtilities.GetDigestName((HashAlgorithmTag)ecKey.HashAlgorithm));

            RFC6637KDFCalculator rfc6637KDFCalculator = new RFC6637KDFCalculator(digest, ecKey.SymmetricKeyAlgorithm);

            byte[] keyBytes = rfc6637KDFCalculator.CreateKey(ecKey.CurveOid, S, getFingerprint(privateKey.PublicKeyPacket));

            KeyParameter keyEncryptionKey = ParameterUtilities.CreateKeyParameter(
                PgpUtilities.GetSymmetricCipherName((SymmetricKeyAlgorithmTag)ecKey.SymmetricKeyAlgorithm),
                keyBytes);

            try
            {
                c.Init(false, keyEncryptionKey);
                byte[] paddedSessionKey = c.Unwrap(keyEnc, 0, keyEnc.Length);

                return UnpadSessionData(paddedSessionKey);
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("error setting asymmetric cipher", e);
            }
        }

        private byte[] UnpadSessionData(byte[] encoded)
        {
            byte padValue = encoded[encoded.Length - 1];

            for (int i = encoded.Length - padValue; i != encoded.Length; i++)
            {
                if (encoded[i] != padValue)
                {
                    throw new PgpException("bad padding found in session data");
                }
            }

            byte[] taggedKey = new byte[encoded.Length - padValue];

            Array.Copy(encoded, 0, taggedKey, 0, taggedKey.Length);
            return taggedKey;
        }

		private byte[] FetchSymmetricKeyData(
			PgpPrivateKey privKey)
		{
			IBufferedCipher c1 = GetKeyCipher(keyData.Algorithm);

			try
			{
				c1.Init(false, privKey.Key);
			}
			catch (InvalidKeyException e)
			{
				throw new PgpException("error setting asymmetric cipher", e);
			}

			BigInteger[] keyD = keyData.GetEncSessionKey();

			if (keyData.Algorithm == PublicKeyAlgorithmTag.RsaEncrypt
				|| keyData.Algorithm == PublicKeyAlgorithmTag.RsaGeneral)
			{
				c1.ProcessBytes(keyD[0].ToByteArrayUnsigned());
			}
			else
			{
				ElGamalPrivateKeyParameters k = (ElGamalPrivateKeyParameters)privKey.Key;
				int size = (k.Parameters.P.BitLength + 7) / 8;

				byte[] bi = keyD[0].ToByteArray();

				int diff = bi.Length - size;
				if (diff >= 0)
				{
					c1.ProcessBytes(bi, diff, size);
				}
				else
				{
					byte[] zeros = new byte[-diff];
					c1.ProcessBytes(zeros);
					c1.ProcessBytes(bi);
				}

				bi = keyD[1].ToByteArray();

				diff = bi.Length - size;
				if (diff >= 0)
				{
					c1.ProcessBytes(bi, diff, size);
				}
				else
				{
					byte[] zeros = new byte[-diff];
					c1.ProcessBytes(zeros);
					c1.ProcessBytes(bi);
				}
			}

			byte[] plain;
			try
			{
				plain = c1.DoFinal();
			}
			catch (Exception e)
			{
				throw new PgpException("exception decrypting secret key", e);
			}

			if (!ConfirmCheckSum(plain))
				throw new PgpKeyValidationException("key checksum failed");

			return plain;
		}
	}
}
