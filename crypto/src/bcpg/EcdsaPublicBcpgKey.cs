using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Bcpg
{
    /**
     * base class for an ECDSA Public Key.
     */
    public class EcdsaPublicBcpgKey : EcPublicBcpgKey
    {
        /**
         * @param in the stream to read the packet from.
         */
        public EcdsaPublicBcpgKey(
            BcpgInputStream bcpgIn) : base(bcpgIn)
        {
        }

        public EcdsaPublicBcpgKey(
            DerObjectIdentifier oid,
            ECPoint point) : base(oid, point)
        {
        }

    }
}
