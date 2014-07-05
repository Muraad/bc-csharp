using System;
using System.IO;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Bcpg
{
    
    /// <summary>
    /// base class for an EC Public Key.
    /// </summary>
    public abstract class EcPublicBcpgKey : BcpgObject, IBcpgKey
    {
        DerObjectIdentifier oid;
        ECPoint point;

        /**
         * @param in the stream to read the packet from.
         */
        protected EcPublicBcpgKey(
            BcpgInputStream input)
        {
            this.oid = DerObjectIdentifier.GetInstance(DerObjectIdentifier.FromByteArray(readBytesOfEncodedLength(input)));
            this.point = decodePoint(new MPInteger(input).Value, oid);
        }

        protected EcPublicBcpgKey(
            DerObjectIdentifier oid,
            ECPoint point)
        {
            this.point = point.Normalize();
            this.oid = oid;
        }

        protected EcPublicBcpgKey(
            BigInteger encodedPoint,
            DerObjectIdentifier oid)
        {
            this.point = decodePoint(encodedPoint, oid);
            this.oid = oid;
        }

        public string Format { get { return "PGP"; } }

        /// <summary>Return the standard PGP encoding of the key.</summary>
		public override byte[] GetEncoded()
		{
			try
			{
				return base.GetEncoded();
			}
			catch (Exception)
			{
				return null;
			}
		}

        public override void Encode(
            BcpgOutputStream outStream)
        {
            byte[] oid = this.oid.GetEncoded();
            outStream.Write(oid, 1, oid.Length - 1);

            MPInteger point = new MPInteger(new BigInteger(1, this.point.GetEncoded()));
            outStream.WriteObject(point);
        }

        public ECPoint Point { get { return point; } }

        public DerObjectIdentifier CurveOid { get { return oid; } }

        protected static byte[] readBytesOfEncodedLength(
            BcpgInputStream inputStream)
        {
            int length = inputStream.ReadByte();
            if (length == 0 || length == 0xFF)
            {
                throw new OpenPgp.PgpException("future extensions not yet implemented.");
            }

            byte[] buffer = new byte[length + 2];
            inputStream.ReadFully(buffer, 2, buffer.Length - 2);
            buffer[0] = (byte)0x06;
            buffer[1] = (byte)length;

            return buffer;
        }

        private static ECPoint decodePoint(
            BigInteger encodedPoint,
            DerObjectIdentifier oid)
        {
            X9ECParameters curve = ECNamedCurveTable.GetByOid(oid);
            if (curve == null)
            {
                throw new System.IO.IOException(oid.Id + " does not match any known curve.");
            }
            if (!ECAlgorithms.IsFpCurve(curve.Curve))
            {
                throw new System.IO.IOException("Only prime field curves are supported.");
            }

            return curve.Curve.DecodePoint(encodedPoint.ToByteArrayUnsigned());
        }
    }
}

