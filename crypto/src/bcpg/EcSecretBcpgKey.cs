using System;

using System.IO;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    public class ECSecretBCPGKey : BcpgObject, IBcpgKey
    {
        MPInteger x;

        public ECSecretBCPGKey(
            BcpgInputStream inputStream)
        {
            this.x = new MPInteger(inputStream);
        }

        public ECSecretBCPGKey(
            BigInteger x)
        {
            this.x = new MPInteger(x);
        }

        public string Format { get{return "PGP";}}


        /**
         * return the standard PGP encoding of the key.
         *
         * @see org.bouncycastle.bcpg.BCPGKey#getEncoded()
         */
        public override byte[] GetEncoded()
        {
            try
            {
                MemoryStream bOut = new MemoryStream();
                BcpgOutputStream pgpOut = new BcpgOutputStream(bOut);

                pgpOut.WriteObject(this);

                return bOut.ToArray();
            }
            catch (IOException e)
            {
                return null;
            }
        }

        public override void Encode(
            BcpgOutputStream output)
        {
            output.WriteObject(x);
        }

        public BigInteger X { get { return x.Value; } }

    }
}
