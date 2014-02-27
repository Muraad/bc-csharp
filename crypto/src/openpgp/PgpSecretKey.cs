using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>General class to handle a PGP secret key object.</remarks>
    public class PgpSecretKey
    {
        public static readonly int SHA1_LENGTH = 20;
        public static readonly int SHA224_LENGTH = 28;
        public static readonly int SHA256_LENGTH = 32;
        public static readonly int SHA384_LENGTH = 48;
        public static readonly int SHA512_LENGTH = 64;

        private readonly SecretKeyPacket secret;
        private readonly PgpPublicKey pub;

<<<<<<< HEAD
        internal PgpSecretKey(
            SecretKeyPacket secret,
            PgpPublicKey pub)
        {
            this.secret = secret;
            this.pub = pub;
        }
=======
<<<<<<< HEAD
		internal PgpSecretKey(
			SecretKeyPacket	secret,
			PgpPublicKey	pub)
		{
			this.secret = secret;
			this.pub = pub;
		}
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7

        //OWN
        internal PgpSecretKey(
            PgpPrivateKey privKey,
            PgpPublicKey pubKey,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            bool useSha1,
            SecureRandom rand)
            : this(privKey, pubKey, encAlgorithm, passPhrase, (useSha1) ? HashAlgorithmTag.Sha1 : HashAlgorithmTag.None, rand, false)
        {
        }

        #region Own PgpSecretKey constructor

        internal PgpSecretKey(
            PgpPrivateKey privKey,
            PgpPublicKey pubKey,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            HashAlgorithmTag s2kDigest,
            SecureRandom rand)
            : this(privKey, pubKey, encAlgorithm, passPhrase, s2kDigest, rand, false)
        {
        }

        #endregion

<<<<<<< HEAD
=======

        // OWN
		/*internal PgpSecretKey(
			PgpPrivateKey				privKey,
			PgpPublicKey				pubKey,
			SymmetricKeyAlgorithmTag	encAlgorithm,
=======
        internal PgpSecretKey(
            SecretKeyPacket	secret,
            PgpPublicKey	pub)
        {
            this.secret = secret;
            this.pub = pub;
        }

        internal PgpSecretKey(
            PgpPrivateKey				privKey,
            PgpPublicKey				pubKey,
            SymmetricKeyAlgorithmTag	encAlgorithm,
>>>>>>> upstream/master
            char[]						passPhrase,
            bool						useSha1,
            SecureRandom				rand)
            : this(privKey, pubKey, encAlgorithm, passPhrase, useSha1, rand, false)
        {
        }

        internal PgpSecretKey(
            PgpPrivateKey				privKey,
            PgpPublicKey				pubKey,
            SymmetricKeyAlgorithmTag	encAlgorithm,
            char[]						passPhrase,
            bool						useSha1,
            SecureRandom				rand,
            bool						isMasterKey)
        {
            BcpgObject secKey;

            this.pub = pubKey;

            switch (pubKey.Algorithm)
            {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaSign:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    RsaPrivateCrtKeyParameters rsK = (RsaPrivateCrtKeyParameters) privKey.Key;
                    secKey = new RsaSecretBcpgKey(rsK.Exponent, rsK.P, rsK.Q);
                    break;
                case PublicKeyAlgorithmTag.Dsa:
                    DsaPrivateKeyParameters dsK = (DsaPrivateKeyParameters) privKey.Key;
                    secKey = new DsaSecretBcpgKey(dsK.X);
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    ElGamalPrivateKeyParameters esK = (ElGamalPrivateKeyParameters) privKey.Key;
                    secKey = new ElGamalSecretBcpgKey(esK.X);
                    break;
                default:
                    throw new PgpException("unknown key class");
            }

            try
            {
                MemoryStream bOut = new MemoryStream();
                BcpgOutputStream pOut = new BcpgOutputStream(bOut);

<<<<<<< HEAD
				pOut.WriteObject(secKey);

				byte[] keyData = bOut.ToArray();

                // Create checksum over private key data written via pOut(bOut)
				byte[] checksumBytes = Checksum(useSha1, keyData, keyData.Length);

                // Add the checksum to the private key data in pOut
				pOut.Write(checksumBytes);
=======
                pOut.WriteObject(secKey);

                byte[] keyData = bOut.ToArray();
                byte[] checksumData = Checksum(useSha1, keyData, keyData.Length);
>>>>>>> upstream/master

                keyData = Arrays.Concatenate(keyData, checksumData);

                if (encAlgorithm == SymmetricKeyAlgorithmTag.Null)
                {
<<<<<<< HEAD
					S2k s2k;
					byte[] iv;

                    // in bOutData is the private key data plus the (maybe SHA1) checksum.
                    // The key is encrypted with given SymmetricKeyAlgorithm. (for example AES256 or CAST5)
					byte[] encData = EncryptKeyData(bOutData, encAlgorithm, passPhrase, rand, out s2k, out iv);

					int s2kUsage = useSha1
						?	SecretKeyPacket.UsageSha1
						:	SecretKeyPacket.UsageChecksum;
					if (isMasterKey)
					{
						this.secret = new SecretKeyPacket(pub.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
					}
					else
					{
						this.secret = new SecretSubkeyPacket(pub.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
					}
				}
=======
                    if (isMasterKey)
                    {
                        this.secret = new SecretKeyPacket(pub.publicPk, encAlgorithm, null, null, keyData);
                    }
                    else
                    {
                        this.secret = new SecretSubkeyPacket(pub.publicPk, encAlgorithm, null, null, keyData);
                    }
                }
                else
                {
                    S2k s2k;
                    byte[] iv;

                    byte[] encData;
                    if (pub.Version >= 4)
                    {
                        encData = EncryptKeyData(keyData, encAlgorithm, passPhrase, rand, out s2k, out iv);
                    }
                    else
                    {
                        // TODO v3 RSA key encryption
                        throw Platform.CreateNotImplementedException("v3 RSA");
                    }

                    int s2kUsage = useSha1
                        ?	SecretKeyPacket.UsageSha1
                        :	SecretKeyPacket.UsageChecksum;

                    if (isMasterKey)
                    {
                        this.secret = new SecretKeyPacket(pub.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
                    }
                    else
                    {
                        this.secret = new SecretSubkeyPacket(pub.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
                    }
                }
>>>>>>> upstream/master
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception encrypting key", e);
            }
        }*/

>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
        #region OWN PgpSecretKey internal constructor that takes s2kDigest parameter

        internal PgpSecretKey(
            PgpPrivateKey privKey,
            PgpPublicKey pubKey,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            HashAlgorithmTag s2kDigest,
            SecureRandom rand,
            bool isMasterKey)
        {
            BcpgObject secKey;

            this.pub = pubKey;

            switch (pubKey.Algorithm)
            {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaSign:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    RsaPrivateCrtKeyParameters rsK = (RsaPrivateCrtKeyParameters)privKey.Key;
                    secKey = new RsaSecretBcpgKey(rsK.Exponent, rsK.P, rsK.Q);
                    break;
                case PublicKeyAlgorithmTag.Dsa:
                    DsaPrivateKeyParameters dsK = (DsaPrivateKeyParameters)privKey.Key;
                    secKey = new DsaSecretBcpgKey(dsK.X);
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    ElGamalPrivateKeyParameters esK = (ElGamalPrivateKeyParameters)privKey.Key;
                    secKey = new ElGamalSecretBcpgKey(esK.X);
                    break;
                default:
                    throw new PgpException("unknown key class");
            }

            try
            {
                MemoryStream bOut = new MemoryStream();
                BcpgOutputStream pOut = new BcpgOutputStream(bOut);

                pOut.WriteObject(secKey);

                byte[] keyData = bOut.ToArray();

                // New Checksum is used if s2kDigest is None then normal checksum calculatin is used.
                byte[] checksumData = Checksum(s2kDigest, keyData, keyData.Length, false);

                keyData = Arrays.Concatenate(keyData, checksumData);

                if (encAlgorithm == SymmetricKeyAlgorithmTag.Null)
                {
                    if (isMasterKey)
                    {
                        this.secret = new SecretKeyPacket(pub.publicPk, encAlgorithm, null, null, keyData);
                    }
                    else
                    {
                        this.secret = new SecretSubkeyPacket(pub.publicPk, encAlgorithm, null, null, keyData);
                    }
                }
                else
                {
                    S2k s2k;
                    byte[] iv;

                    // in bOutData is the private key data plus the (hashed) checksum.
                    // The key is encrypted with given SymmetricKeyAlgorithm. (for example AES256 or CAST5)
                    byte[] encData;
                    if (pub.Version >= 4)
                    {
                        encData = EncryptKeyData(keyData, encAlgorithm, passPhrase, rand, out s2k, out iv, s2kDigest);
                    }
                    else
                    {
                        // TODO v3 RSA key encryption
                        throw Platform.CreateNotImplementedException("v3 RSA");
                    }

                    int s2kUsage = SecretKeyPacket.UsageDigest;

                    if (s2kDigest == HashAlgorithmTag.None)
                        s2kUsage = SecretKeyPacket.UsageChecksum;

                    if (isMasterKey)
                    {
                        this.secret = new SecretKeyPacket(pub.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
                    }
                    else
                    {
                        this.secret = new SecretSubkeyPacket(pub.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
                    }
                }
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception encrypting key", e);
            }
        }

<<<<<<< HEAD
        #endregion

        // TODO: Think about replacing default UsageSha1 with SHA512
=======
>>>>>>> upstream/master
        public PgpSecretKey(
<<<<<<< HEAD
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom rand)
            : this(certificationLevel, keyPair, id, encAlgorithm, passPhrase, false, hashedPackets, unhashedPackets, rand)
        {
        }
=======
            int							certificationLevel,
            PgpKeyPair					keyPair,
            string						id,
            SymmetricKeyAlgorithmTag	encAlgorithm,
            char[]						passPhrase,
            PgpSignatureSubpacketVector	hashedPackets,
            PgpSignatureSubpacketVector	unhashedPackets,
            SecureRandom				rand)
<<<<<<< HEAD
			: this(certificationLevel, keyPair, id, encAlgorithm, passPhrase, false, hashedPackets, unhashedPackets, rand)
		{
		}
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7

        //OWN
        public PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom rand)
            : this(keyPair.PrivateKey, CertifiedPublicKey(certificationLevel, keyPair, id, hashedPackets, unhashedPackets), encAlgorithm, passPhrase, (useSha1) ? HashAlgorithmTag.Sha1 : HashAlgorithmTag.None, rand, true)
        {
        }

        #region Own PgpSecretKey constructor with s2kDigest parameter

        public PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            HashAlgorithmTag s2kDigest,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom rand)
            : this(keyPair.PrivateKey,
                    CertifiedPublicKey(certificationLevel, keyPair, id, hashedPackets, unhashedPackets, (s2kDigest == HashAlgorithmTag.None) ? HashAlgorithmTag.Sha1 : s2kDigest),
                    encAlgorithm,
                    passPhrase,
                    s2kDigest,
                    rand,
                    true)
        {
        }

        #endregion

        //Now has a digest parameter that is sha1 by default, but other can be used now.
        private static PgpPublicKey CertifiedPublicKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            HashAlgorithmTag digest = HashAlgorithmTag.Sha1)
        {
            PgpSignatureGenerator sGen;

            // None is not allowed here must be at least Sha1
            if (digest == HashAlgorithmTag.None)
                digest = HashAlgorithmTag.Sha1;

            try
            {
                sGen = new PgpSignatureGenerator(keyPair.PublicKey.Algorithm, digest);
            }
            catch (Exception e)
            {
                throw new PgpException("Creating signature generator: " + e.Message, e);
            }

            //
            // Generate the certification
            //
            sGen.InitSign(certificationLevel, keyPair.PrivateKey);

            sGen.SetHashedSubpackets(hashedPackets);
            sGen.SetUnhashedSubpackets(unhashedPackets);

<<<<<<< HEAD
            try
            {
=======
			try
=======
            : this(certificationLevel, keyPair, id, encAlgorithm, passPhrase, false, hashedPackets, unhashedPackets, rand)
        {
        }

        public PgpSecretKey(
            int							certificationLevel,
            PgpKeyPair					keyPair,
            string						id,
            SymmetricKeyAlgorithmTag	encAlgorithm,
            char[]						passPhrase,
            bool						useSha1,
            PgpSignatureSubpacketVector	hashedPackets,
            PgpSignatureSubpacketVector	unhashedPackets,
            SecureRandom				rand)
            : this(keyPair.PrivateKey, CertifiedPublicKey(certificationLevel, keyPair, id, hashedPackets, unhashedPackets), encAlgorithm, passPhrase, useSha1, rand, true)
        {
        }

        private static PgpPublicKey CertifiedPublicKey(
            int							certificationLevel,
            PgpKeyPair					keyPair,
            string						id,
            PgpSignatureSubpacketVector	hashedPackets,
            PgpSignatureSubpacketVector	unhashedPackets)
        {
            PgpSignatureGenerator sGen;
            try
>>>>>>> upstream/master
            {
                sGen = new PgpSignatureGenerator(keyPair.PublicKey.Algorithm, HashAlgorithmTag.Sha1);
            }
            catch (Exception e)
            {
                throw new PgpException("Creating signature generator: " + e.Message, e);
            }

            //
            // Generate the certification
            //
            sGen.InitSign(certificationLevel, keyPair.PrivateKey);

            sGen.SetHashedSubpackets(hashedPackets);
            sGen.SetUnhashedSubpackets(unhashedPackets);

            try
            {
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
                PgpSignature certification = sGen.GenerateCertification(id, keyPair.PublicKey);
                return PgpPublicKey.AddCertification(keyPair.PublicKey, id, certification);
            }
            catch (Exception e)
            {
                throw new PgpException("Exception doing certification: " + e.Message, e);
            }
        }

<<<<<<< HEAD
        // is using bad default 
        public PgpSecretKey(
            int certificationLevel,
            PublicKeyAlgorithmTag algorithm,
            AsymmetricKeyParameter pubKey,
            AsymmetricKeyParameter privKey,
            DateTime time,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom rand)
=======
<<<<<<< HEAD

        // is using bad default 
		public PgpSecretKey(
=======
        public PgpSecretKey(
>>>>>>> upstream/master
            int							certificationLevel,
            PublicKeyAlgorithmTag		algorithm,
            AsymmetricKeyParameter		pubKey,
            AsymmetricKeyParameter		privKey,
            DateTime					time,
            string						id,
            SymmetricKeyAlgorithmTag	encAlgorithm,
            char[]						passPhrase,
            PgpSignatureSubpacketVector	hashedPackets,
            PgpSignatureSubpacketVector	unhashedPackets,
            SecureRandom				rand)
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
            : this(certificationLevel,
                new PgpKeyPair(algorithm, pubKey, privKey, time),
                id, encAlgorithm, passPhrase, hashedPackets, unhashedPackets, rand)
        {
        }

<<<<<<< HEAD
        // OWN
        public PgpSecretKey(
            int certificationLevel,
            PublicKeyAlgorithmTag algorithm,
            AsymmetricKeyParameter pubKey,
            AsymmetricKeyParameter privKey,
            DateTime time,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom rand)
            : this(certificationLevel, new PgpKeyPair(algorithm, pubKey, privKey, time), id, encAlgorithm, passPhrase, useSha1, hashedPackets, unhashedPackets, rand)
        {
        }

        #region Own PgpSecretKey constructor with s2kDigest parameter

        public PgpSecretKey(
            int certificationLevel,
            PublicKeyAlgorithmTag algorithm,
            AsymmetricKeyParameter pubKey,
            AsymmetricKeyParameter privKey,
            DateTime time,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            HashAlgorithmTag s2kDigest,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom rand)
            : this(certificationLevel, new PgpKeyPair(algorithm, pubKey, privKey, time), id, encAlgorithm, passPhrase, s2kDigest, hashedPackets, unhashedPackets, rand)
        {
        }

        #endregion


        /// <summary>Detect if the Secret Key's Private Key is empty or not</summary>
        public bool IsPrivateKeyEmpty
        {
            get
            {
                byte[] secKeyData = secret.GetSecretKeyData();

                return secKeyData == null || secKeyData.Length < 1;
            }
        }

        /// <summary>
<<<<<<< HEAD
        /// Check if this key has an algorithm type that makes it suitable to use for signing.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if this key algorithm is suitable for use with signing.
        /// </returns>
        public bool IsSigningKey
        {
            get
            {
                switch (pub.Algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaGeneral:
                    case PublicKeyAlgorithmTag.RsaSign:
                    case PublicKeyAlgorithmTag.Dsa:
                    case PublicKeyAlgorithmTag.ECDsa:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        return true;
                    default:
                        return false;
                }
            }
        }

=======
		/// Check if this key has an algorithm type that makes it suitable to use for signing.
		/// </summary>
		/// <remarks>
		/// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
		/// determining the preferred use of the key.
		/// </remarks>
		/// <returns>
		/// <c>true</c> if this key algorithm is suitable for use with signing.
		/// </returns>
		public bool IsSigningKey
=======
        public PgpSecretKey(
            int							certificationLevel,
            PublicKeyAlgorithmTag		algorithm,
            AsymmetricKeyParameter		pubKey,
            AsymmetricKeyParameter		privKey,
            DateTime					time,
            string						id,
            SymmetricKeyAlgorithmTag	encAlgorithm,
            char[]						passPhrase,
            bool						useSha1,
            PgpSignatureSubpacketVector	hashedPackets,
            PgpSignatureSubpacketVector	unhashedPackets,
            SecureRandom				rand)
            : this(certificationLevel, new PgpKeyPair(algorithm, pubKey, privKey, time), id, encAlgorithm, passPhrase, useSha1, hashedPackets, unhashedPackets, rand)
>>>>>>> upstream/master
        {
        }

        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for signing.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if this key algorithm is suitable for use with signing.
        /// </returns>
        public bool IsSigningKey
        {
            get
            {
                switch (pub.Algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaGeneral:
                    case PublicKeyAlgorithmTag.RsaSign:
                    case PublicKeyAlgorithmTag.Dsa:
                    case PublicKeyAlgorithmTag.ECDsa:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        return true;
                    default:
                        return false;
                }
            }
        }

>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
        /// <summary>True, if this is a master key.</summary>
        public bool IsMasterKey
        {
            get { return pub.IsMasterKey; }
        }

<<<<<<< HEAD
=======
        /// <summary>Detect if the Secret Key's Private Key is empty or not</summary>
        public bool IsPrivateKeyEmpty
        {
            get
            {
                byte[] secKeyData = secret.GetSecretKeyData();

                return secKeyData == null || secKeyData.Length < 1;
            }
        }

>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
        /// <summary>The algorithm the key is encrypted with.</summary>
        public SymmetricKeyAlgorithmTag KeyEncryptionAlgorithm
        {
            get { return secret.EncAlgorithm; }
        }

        /// <summary>The key ID of the public key associated with this key.</summary>
        public long KeyId
        {
            get { return pub.KeyId; }
        }

        /// <summary>The public key associated with this key.</summary>
        public PgpPublicKey PublicKey
        {
            get { return pub; }
        }

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable UserIds
        {
            get { return pub.GetUserIds(); }
        }

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable UserAttributes
        {
            get { return pub.GetUserAttributes(); }
        }

<<<<<<< HEAD
        // OWN:
        // s2k password checksum can now use all Digest algorithms not only SHA1
        // secret.s2k.HashAlgorithm is used.
<<<<<<< HEAD
        private byte[] ExtractKeyData(
=======
		private byte[] ExtractKeyData(
=======
        private byte[] ExtractKeyData(
>>>>>>> upstream/master
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
            char[] passPhrase)
        {
            SymmetricKeyAlgorithmTag alg = secret.EncAlgorithm;
            byte[] encData = secret.GetSecretKeyData();

            if (alg == SymmetricKeyAlgorithmTag.Null)
                // TODO Check checksum here?
                return encData;

<<<<<<< HEAD

=======
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
            IBufferedCipher c = null;
            try
            {
                string cName = PgpUtilities.GetSymmetricCipherName(alg);
                c = CipherUtilities.GetCipher(cName + "/CFB/NoPadding");
            }
            catch (Exception e)
<<<<<<< HEAD
            {
                throw new PgpException("Exception creating cipher", e);
            }

            // TODO Factor this block out as 'encryptData'
            try
            {
                byte[] data;
                KeyParameter key = PgpUtilities.MakeKeyFromPassPhrase(secret.EncAlgorithm, secret.S2k, passPhrase);
                byte[] iv = secret.GetIV();

=======
            {
                throw new PgpException("Exception creating cipher", e);
            }

            // TODO Factor this block out as 'decryptData'
            try
            {
                KeyParameter key = PgpUtilities.MakeKeyFromPassPhrase(secret.EncAlgorithm, secret.S2k, passPhrase);
                byte[] iv = secret.GetIV();
                byte[] data;

>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
                if (secret.PublicKeyPacket.Version >= 4)
                {
                    c.Init(false, new ParametersWithIV(key, iv));

                    data = c.DoFinal(encData);

<<<<<<< HEAD
                    bool useDigest = secret.S2kUsage == SecretKeyPacket.UsageDigest;
=======
<<<<<<< HEAD
					bool useDigest = secret.S2kUsage == SecretKeyPacket.UsageDigest;
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
                    byte[] check;

                    if (useDigest)
                        check = Checksum(secret.S2k.HashAlgorithm, data, data.Length, true);
                    else
                        check = Checksum(false, data, data.Length - 2);

                    /*Console.WriteLine("--------------------------------------------------------------");
                    Console.WriteLine("Checksum: ");
                    foreach (byte ch in check)
                        Console.Write(ch);
                    Console.WriteLine("\nData: " + data);
                    foreach (byte d in data)
                        Console.Write(d);
                    Console.WriteLine("--------------------------------------------------------------");*/

<<<<<<< HEAD
=======
					for (int i = 0; i != check.Length; i++)
					{
						if (check[i] != data[data.Length - check.Length + i])
						{
                            
							throw new PgpException("Checksum mismatch at " + i + " of " + check.Length);
						}
					}
				}
=======
                    bool useSha1 = secret.S2kUsage == SecretKeyPacket.UsageSha1;
                    byte[] check = Checksum(useSha1, data, (useSha1) ? data.Length - 20 : data.Length - 2);

>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
                    for (int i = 0; i != check.Length; i++)
                    {
                        if (check[i] != data[data.Length - check.Length + i])
                        {
<<<<<<< HEAD

=======
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
                            throw new PgpException("Checksum mismatch at " + i + " of " + check.Length);
                        }
                    }
                }
<<<<<<< HEAD
                else // version 2 or 3, RSA only.
                {
                    data = new byte[encData.Length];
                    iv = Arrays.Clone(iv);
=======
>>>>>>> upstream/master
                else // version 2 or 3, RSA only.
                {
                    data = new byte[encData.Length];

                    iv = Arrays.Clone(iv);

>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
                    //
                    // read in the four numbers
                    //
                    int pos = 0;

                    for (int i = 0; i != 4; i++)
                    {
                        c.Init(false, new ParametersWithIV(key, iv));

                        int encLen = (((encData[pos] << 8) | (encData[pos + 1] & 0xff)) + 7) / 8;

                        data[pos] = encData[pos];
                        data[pos + 1] = encData[pos + 1];
                        pos += 2;

                        c.DoFinal(encData, pos, encLen, data, pos);
                        pos += encLen;

                        if (i != 3)
                        {
                            Array.Copy(encData, pos - iv.Length, iv, 0, iv.Length);
                        }
                    }

<<<<<<< HEAD
                    //
                    // verify Checksum
                    //
=======
                    //
                    // verify and copy checksum
                    //
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7

                    data[pos] = encData[pos];
                    data[pos + 1] = encData[pos + 1];

                    int cs = ((encData[pos] << 8) & 0xff00) | (encData[pos + 1] & 0xff);
                    int calcCs = 0;
                    for (int j = 0; j < pos; j++)
                    {
                        calcCs += data[j] & 0xff;
                    }

                    calcCs &= 0xffff;
                    if (calcCs != cs)
                    {
                        throw new PgpException("Checksum mismatch: passphrase wrong, expected "
                            + cs.ToString("X")
                            + " found " + calcCs.ToString("X"));
                    }
                }

                return data;
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception decrypting key", e);
            }
        }

<<<<<<< HEAD

<<<<<<< HEAD
        /// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
        public PgpPrivateKey ExtractPrivateKey(
            char[] passPhrase)
        {
            byte[] secKeyData = secret.GetSecretKeyData();
=======
		/// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
=======
        /// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
>>>>>>> upstream/master
        public PgpPrivateKey ExtractPrivateKey(
            char[] passPhrase)
        {
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
            if (IsPrivateKeyEmpty)
                return null;

            PublicKeyPacket pubPk = secret.PublicKeyPacket;
            try
            {
                byte[] data = ExtractKeyData(passPhrase);
                BcpgInputStream bcpgIn = BcpgInputStream.Wrap(new MemoryStream(data, false));
                AsymmetricKeyParameter privateKey;
                switch (pubPk.Algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                    case PublicKeyAlgorithmTag.RsaSign:
                        RsaPublicBcpgKey rsaPub = (RsaPublicBcpgKey)pubPk.Key;
                        RsaSecretBcpgKey rsaPriv = new RsaSecretBcpgKey(bcpgIn);
                        RsaPrivateCrtKeyParameters rsaPrivSpec = new RsaPrivateCrtKeyParameters(
                            rsaPriv.Modulus,
                            rsaPub.PublicExponent,
                            rsaPriv.PrivateExponent,
                            rsaPriv.PrimeP,
                            rsaPriv.PrimeQ,
                            rsaPriv.PrimeExponentP,
                            rsaPriv.PrimeExponentQ,
                            rsaPriv.CrtCoefficient);
                        privateKey = rsaPrivSpec;
                        break;
                    case PublicKeyAlgorithmTag.Dsa:
                        DsaPublicBcpgKey dsaPub = (DsaPublicBcpgKey)pubPk.Key;
                        DsaSecretBcpgKey dsaPriv = new DsaSecretBcpgKey(bcpgIn);
                        DsaParameters dsaParams = new DsaParameters(dsaPub.P, dsaPub.Q, dsaPub.G);
                        privateKey = new DsaPrivateKeyParameters(dsaPriv.X, dsaParams);
                        break;
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        ElGamalPublicBcpgKey elPub = (ElGamalPublicBcpgKey)pubPk.Key;
                        ElGamalSecretBcpgKey elPriv = new ElGamalSecretBcpgKey(bcpgIn);
                        ElGamalParameters elParams = new ElGamalParameters(elPub.P, elPub.G);
                        privateKey = new ElGamalPrivateKeyParameters(elPriv.X, elParams);
                        break;
                    default:
                        throw new PgpException("unknown public key algorithm encountered");
                }

                return new PgpPrivateKey(privateKey, KeyId);
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception constructing key", e);
            }
        }

<<<<<<< HEAD
        private static byte[] Checksum(
            bool useSha1,
            byte[] bytes,
            int length)
        {
            if (useSha1)
            {
                try
                {
                    IDigest dig = DigestUtilities.GetDigest("SHA1");
                    dig.BlockUpdate(bytes, 0, length);
                    return DigestUtilities.DoFinal(dig);
                }
                //catch (NoSuchAlgorithmException e)
                catch (Exception e)
                {
                    throw new PgpException("Can't find SHA-1", e);
                }
            }
            else
            {
                int Checksum = 0;
                for (int i = 0; i != length; i++)
                {
                    Checksum += bytes[i];
                }

                return new byte[] { (byte)(Checksum >> 8), (byte)Checksum };
            }
        }
=======
<<<<<<< HEAD
		private static byte[] Checksum(
			bool	useSha1,
			byte[]	bytes,
			int		length)
		{
			if (useSha1)
			{
				try
				{
					IDigest dig = DigestUtilities.GetDigest("SHA1");
					dig.BlockUpdate(bytes, 0, length);
					return DigestUtilities.DoFinal(dig);
				}
				//catch (NoSuchAlgorithmException e)
				catch (Exception e)
				{
					throw new PgpException("Can't find SHA-1", e);
				}
			}
			else
			{
				int Checksum = 0;
				for (int i = 0; i != length; i++)
				{
					Checksum += bytes[i];
				}

				return new byte[] { (byte)(Checksum >> 8), (byte)Checksum };
			}
		}
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7

        #region Own Checksum with given Hash algorithm

        private static byte[] Checksum(
            HashAlgorithmTag s2kDigest,
            byte[] bytes,
            int length,
            bool cutLength)
        {
            if (s2kDigest == HashAlgorithmTag.None)
            {
                if (cutLength)
                    length -= 2;
                int Checksum = 0;
                for (int i = 0; i != length; i++)
                {
                    Checksum += bytes[i];
                }

                return new byte[] { (byte)(Checksum >> 8), (byte)Checksum };
            }
            else
            {
                try
                {
                    IDigest dig = null;
                    switch (s2kDigest)
                    {
                        case HashAlgorithmTag.Sha1:
                            dig = new Sha1Digest();
                            if (cutLength)
                                length -= SHA1_LENGTH;
                            break;
                        case HashAlgorithmTag.Sha224:
                            dig = new Sha224Digest();
                            if (cutLength)
                                length -= SHA224_LENGTH;
                            break;
                        case HashAlgorithmTag.Sha256:
                            dig = new Sha256Digest();
                            if (cutLength)
                                length -= SHA256_LENGTH;
                            break;
                        case HashAlgorithmTag.Sha384:
                            dig = new Sha384Digest();
                            if (cutLength)
                                length -= SHA384_LENGTH;
                            break;
                        case HashAlgorithmTag.Sha512:
                            dig = new Sha512Digest();
                            if (cutLength)
                                length -= SHA512_LENGTH;
                            break;
                    }
=======
        private static byte[] Checksum(
            bool	useSha1,
            byte[]	bytes,
            int		length)
        {
            if (useSha1)
            {
                try
                {
                    IDigest dig = DigestUtilities.GetDigest("SHA1");
>>>>>>> upstream/master
                    dig.BlockUpdate(bytes, 0, length);
                    return DigestUtilities.DoFinal(dig);
                }
                //catch (NoSuchAlgorithmException e)
                catch (Exception e)
                {
<<<<<<< HEAD
                    throw new PgpException("Can't find Digest", e);
                }
            }
        }

        #endregion
=======
                    throw new PgpException("Can't find SHA-1", e);
                }
            }
            else
            {
                int Checksum = 0;
                for (int i = 0; i != length; i++)
                {
                    Checksum += bytes[i];
                }

                return new byte[] { (byte)(Checksum >> 8), (byte)Checksum };
            }
        }
>>>>>>> upstream/master

        public byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();
            Encode(bOut);
            return bOut.ToArray();
        }

        public void Encode(
            Stream outStr)
        {
            BcpgOutputStream bcpgOut = BcpgOutputStream.Wrap(outStr);

            bcpgOut.WritePacket(secret);
            if (pub.trustPk != null)
            {
                bcpgOut.WritePacket(pub.trustPk);
            }

            if (pub.subSigs == null) // is not a sub key
            {
                foreach (PgpSignature keySig in pub.keySigs)
                {
                    keySig.Encode(bcpgOut);
                }

                for (int i = 0; i != pub.ids.Count; i++)
                {
                    object pubID = pub.ids[i];
                    if (pubID is string)
                    {
                        string id = (string)pubID;
                        bcpgOut.WritePacket(new UserIdPacket(id));
                    }
                    else
                    {
                        PgpUserAttributeSubpacketVector v = (PgpUserAttributeSubpacketVector)pubID;
                        bcpgOut.WritePacket(new UserAttributePacket(v.ToSubpacketArray()));
                    }

                    if (pub.idTrusts[i] != null)
                    {
                        bcpgOut.WritePacket((ContainedPacket)pub.idTrusts[i]);
                    }

<<<<<<< HEAD
                    foreach (PgpSignature sig in (IList)pub.idSigs[i])
=======
                    foreach (PgpSignature sig in (IList) pub.idSigs[i])
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
                    {
                        sig.Encode(bcpgOut);
                    }
                }
            }
            else
            {
                foreach (PgpSignature subSig in pub.subSigs)
                {
                    subSig.Encode(bcpgOut);
                }
            }

            // TODO Check that this is right/necessary
            //bcpgOut.Finish();
        }

<<<<<<< HEAD
        /// <summary>
        /// Return a copy of the passed in secret key, encrypted using a new password
        /// and the passed in algorithm.
        /// It will now use the key.secret.s2k.HashAlgorithm to encrypt the private key.
=======
<<<<<<< HEAD
		/// <summary>
		/// Return a copy of the passed in secret key, encrypted using a new password
		/// and the passed in algorithm.
        /// It will now use the key.secret.s2k.HashAlgorithm to encrypt the private key.
		/// </summary>
		/// <param name="key">The PgpSecretKey to be copied.</param>
		/// <param name="oldPassPhrase">The current password for the key.</param>
		/// <param name="newPassPhrase">The new password for the key.</param>
		/// <param name="newEncAlgorithm">The algorithm to be used for the encryption.</param>
		/// <param name="rand">Source of randomness.</param>
=======
        /// <summary>
        /// Return a copy of the passed in secret key, encrypted using a new password
        /// and the passed in algorithm.
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
        /// </summary>
        /// <param name="key">The PgpSecretKey to be copied.</param>
        /// <param name="oldPassPhrase">The current password for the key.</param>
        /// <param name="newPassPhrase">The new password for the key.</param>
        /// <param name="newEncAlgorithm">The algorithm to be used for the encryption.</param>
        /// <param name="rand">Source of randomness.</param>
<<<<<<< HEAD
=======
>>>>>>> upstream/master
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
        public static PgpSecretKey CopyWithNewPassword(
            PgpSecretKey key,
            char[] oldPassPhrase,
            char[] newPassPhrase,
            SymmetricKeyAlgorithmTag newEncAlgorithm,
            SecureRandom rand,
            HashAlgorithmTag digest = HashAlgorithmTag.Sha1)     // Digest is used for s2k and for checksum!
        {
<<<<<<< HEAD
            byte[] rawKeyData = key.ExtractKeyData(oldPassPhrase);
            int s2kUsage = key.secret.S2kUsage;
            byte[] iv = null;
            S2k s2k = null;
            byte[] keyData;
=======
            if (key.IsPrivateKeyEmpty)
                throw new PgpException("no private key in this SecretKey - public key present only.");

            byte[]	rawKeyData = key.ExtractKeyData(oldPassPhrase);
            int		s2kUsage = key.secret.S2kUsage;
            byte[]	iv = null;
            S2k		s2k = null;
            byte[]	keyData;
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
            PublicKeyPacket pubKeyPacket = key.secret.PublicKeyPacket;

            if (newEncAlgorithm == SymmetricKeyAlgorithmTag.Null)
            {
<<<<<<< HEAD
                s2kUsage = SecretKeyPacket.UsageNone;
=======
<<<<<<< HEAD
				s2kUsage = SecretKeyPacket.UsageNone;
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7

                // Is here an error? The if ask for s2kUsage equals UsageSha1 but inside the Checksum (old) is 
                // called with first parameter UsageSha1 = false!!

                // TODO: calculate checksum with HashAlgorithm from s2k.
<<<<<<< HEAD
                if (key.secret.S2kUsage == SecretKeyPacket.UsageDigest)   // SHA-1 hash, need to rewrite Checksum
=======
				if (key.secret.S2kUsage == SecretKeyPacket.UsageDigest)   // SHA-1 hash, need to rewrite Checksum
				{
					keyData = new byte[rawKeyData.Length - 18];

					Array.Copy(rawKeyData, 0, keyData, 0, keyData.Length - 2);

					byte[] check = Checksum(false, keyData, keyData.Length - 2);

					keyData[keyData.Length - 2] = check[0];
					keyData[keyData.Length - 1] = check[1];
				}
				else
				{
					keyData = rawKeyData;
				}
			}
=======
                s2kUsage = SecretKeyPacket.UsageNone;
                if (key.secret.S2kUsage == SecretKeyPacket.UsageSha1)   // SHA-1 hash, need to rewrite Checksum
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
                {
                    keyData = new byte[rawKeyData.Length - 18];

                    Array.Copy(rawKeyData, 0, keyData, 0, keyData.Length - 2);

                    byte[] check = Checksum(false, keyData, keyData.Length - 2);

                    keyData[keyData.Length - 2] = check[0];
                    keyData[keyData.Length - 1] = check[1];
                }
                else
                {
                    keyData = rawKeyData;
                }
            }
<<<<<<< HEAD
            else
            {
                try
                {      // If HashAlgorithm is null then EncryptKeyData uses Sha1, none is not allowed here!.
                    if (pubKeyPacket.Version >= 4)
                    {
                        keyData = EncryptKeyData(rawKeyData, newEncAlgorithm, newPassPhrase, rand, out s2k, out iv, key.secret.S2k.HashAlgorithm);
=======
>>>>>>> upstream/master
            else
            {
                try
                {
<<<<<<< HEAD
                    // Give the EncryptKeyData a s2kdigest parameter 
                    keyData = EncryptKeyData(rawKeyData, 
                                            newEncAlgorithm, 
                                            newPassPhrase, 
                                            rand, 
                                            out s2k,
                                            out iv,
                                            key.secret.S2k.HashAlgorithm);      // If HashAlgorithm is null then EncryptKeyData uses Sha1, none is not allowed here!.
=======
                    if (pubKeyPacket.Version >= 4)
                    {
                        keyData = EncryptKeyData(rawKeyData, newEncAlgorithm, newPassPhrase, rand, out s2k, out iv);
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
                    }
                    else
                    {
                        // TODO v3 RSA key encryption
                        throw Platform.CreateNotImplementedException("v3 RSA");
                    }
<<<<<<< HEAD
=======
>>>>>>> upstream/master
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
                }
                catch (PgpException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new PgpException("Exception encrypting key", e);
                }
            }

            SecretKeyPacket secret;
            if (key.secret is SecretSubkeyPacket)
            {
<<<<<<< HEAD
                secret = new SecretSubkeyPacket(pubKeyPacket, newEncAlgorithm, s2kUsage, s2k, iv, keyData);
            }
            else
            {
                secret = new SecretKeyPacket(pubKeyPacket, newEncAlgorithm, s2kUsage, s2k, iv, keyData);
            }

            return new PgpSecretKey(secret, key.pub);
        }

        /// <summary>Replace the passed public key on the passed in secret key.</summary>
        /// <param name="secretKey">Secret key to change.</param>
        /// <param name="publicKey">New public key.</param>
        /// <returns>A new secret key.</returns>
        /// <exception cref="ArgumentException">If KeyId's do not match.</exception>
        public static PgpSecretKey ReplacePublicKey(
            PgpSecretKey secretKey,
            PgpPublicKey publicKey)
        {
            if (publicKey.KeyId != secretKey.KeyId)
                throw new ArgumentException("KeyId's do not match");

            return new PgpSecretKey(secretKey.secret, publicKey);
        }

        private static byte[] EncryptKeyData(byte[] rawKeyData,
=======
<<<<<<< HEAD
                secret = new SecretSubkeyPacket(key.secret.PublicKeyPacket, newEncAlgorithm, s2kUsage, s2k, iv, keyData);
            }
            else
            {
                secret = new SecretKeyPacket(key.secret.PublicKeyPacket, newEncAlgorithm, s2kUsage, s2k, iv, keyData);
=======
                secret = new SecretSubkeyPacket(pubKeyPacket, newEncAlgorithm, s2kUsage, s2k, iv, keyData);
            }
            else
            {
                secret = new SecretKeyPacket(pubKeyPacket, newEncAlgorithm, s2kUsage, s2k, iv, keyData);
>>>>>>> upstream/master
            }

            return new PgpSecretKey(secret, key.pub);
        }

        /// <summary>Replace the passed the public key on the passed in secret key.</summary>
        /// <param name="secretKey">Secret key to change.</param>
        /// <param name="publicKey">New public key.</param>
        /// <returns>A new secret key.</returns>
        /// <exception cref="ArgumentException">If KeyId's do not match.</exception>
        public static PgpSecretKey ReplacePublicKey(
            PgpSecretKey	secretKey,
            PgpPublicKey	publicKey)
        {
            if (publicKey.KeyId != secretKey.KeyId)
                throw new ArgumentException("KeyId's do not match");

            return new PgpSecretKey(secretKey.secret, publicKey);
        }

<<<<<<< HEAD
		/// <summary>Replace the passed public key on the passed in secret key.</summary>
		/// <param name="secretKey">Secret key to change.</param>
		/// <param name="publicKey">New public key.</param>
		/// <returns>A new secret key.</returns>
		/// <exception cref="ArgumentException">If KeyId's do not match.</exception>
		public static PgpSecretKey ReplacePublicKey(
			PgpSecretKey	secretKey,
			PgpPublicKey	publicKey)
		{
			if (publicKey.KeyId != secretKey.KeyId)
				throw new ArgumentException("KeyId's do not match");

			return new PgpSecretKey(secretKey.secret, publicKey);
		}

        private static byte[] EncryptKeyData(byte[] rawKeyData, 
>>>>>>> 3ea80e3497eeaa439d662a8458bdbff84b0868b7
                                            SymmetricKeyAlgorithmTag encAlgorithm,
                                            char[] passPhrase,
                                            SecureRandom random,
                                            out S2k s2k,
                                            out byte[] iv,
                                            HashAlgorithmTag s2kDigest = HashAlgorithmTag.Sha1)
=======
        private static byte[] EncryptKeyData(
            byte[]						rawKeyData,
            SymmetricKeyAlgorithmTag	encAlgorithm,
            char[]						passPhrase,
            SecureRandom				random,
            out S2k						s2k,
            out byte[]					iv)
>>>>>>> upstream/master
        {
            IBufferedCipher c;
            try
            {
                string cName = PgpUtilities.GetSymmetricCipherName(encAlgorithm);
                c = CipherUtilities.GetCipher(cName + "/CFB/NoPadding");
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }

            byte[] s2kIV = new byte[8];
            random.NextBytes(s2kIV);
<<<<<<< HEAD

            // s2kDigest is not allowed to be None here! PGP specification is using Sha1 always.
            if (s2kDigest == HashAlgorithmTag.None)
                s2kDigest = HashAlgorithmTag.Sha1;

            s2k = new S2k(s2kDigest, s2kIV, 0x60);
=======
            s2k = new S2k(HashAlgorithmTag.Sha1, s2kIV, 0x60);

>>>>>>> upstream/master
            KeyParameter kp = PgpUtilities.MakeKeyFromPassPhrase(encAlgorithm, s2k, passPhrase);

            iv = new byte[c.GetBlockSize()];
            random.NextBytes(iv);

            c.Init(true, new ParametersWithRandom(new ParametersWithIV(kp, iv), random));

            return c.DoFinal(rawKeyData);
        }
<<<<<<< HEAD

=======
>>>>>>> upstream/master
    }
}
