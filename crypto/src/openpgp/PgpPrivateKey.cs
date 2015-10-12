using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>General class to contain a private key for use with other OpenPGP objects.</remarks>
    public class PgpPrivateKey
    {
        private readonly long keyID;
        private readonly PublicKeyPacket publicKeyPacket;
        private readonly AsymmetricKeyParameter privateKey;
<<<<<<< HEAD
        private readonly PublicKeyPacket publicKeyPacket;
		/// <summary>
		/// Create a PgpPrivateKey from a regular private key and the ID of its
		/// associated public key.
=======

        /// <summary>
		/// Create a PgpPrivateKey from a keyID, the associated public data packet, and a regular private key.
>>>>>>> 06ba713c9b19102310675a6c58e07c68d8efb3c7
		/// </summary>
		/// <param name="keyID">ID of the corresponding public key.</param>
        /// <param name="publicKeyPacket">the public key data packet to be associated with this private key.</param>
        /// <param name="privateKey">the private key data packet to be associated with this private key.</param>
        public PgpPrivateKey(
            long                    keyID,
            PublicKeyPacket         publicKeyPacket,
            AsymmetricKeyParameter	privateKey)
        {
			if (!privateKey.IsPrivate)
				throw new ArgumentException("Expected a private key", "privateKey");

            this.keyID = keyID;
            this.publicKeyPacket = publicKeyPacket;
            this.privateKey = privateKey;
        }

<<<<<<< HEAD
        public PgpPrivateKey(
            AsymmetricKeyParameter privateKey,
            long keyId,
            PublicKeyPacket pubKeyPacket)
        {
            if (!privateKey.IsPrivate)
                throw new ArgumentException("Expected a private key", "privateKey");

            this.privateKey = privateKey;
            this.keyId = keyId;
            this.publicKeyPacket = pubKeyPacket;
        }

		/// <summary>The keyId associated with the contained private key.</summary>
=======
        /// <summary>The keyId associated with the contained private key.</summary>
>>>>>>> 06ba713c9b19102310675a6c58e07c68d8efb3c7
        public long KeyId
        {
			get { return keyID; }
        }

        /// <summary>The public key packet associated with this private key, if available.</summary>
        public PublicKeyPacket PublicKeyPacket
        {
            get { return publicKeyPacket; }
        }

        /// <summary>The contained private key.</summary>
        public AsymmetricKeyParameter Key
        {
			get { return privateKey; }
        }

        public PublicKeyPacket PublicKeyPacket
        {
            get { return publicKeyPacket; }
        }
    }
}
