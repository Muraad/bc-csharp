using System;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public abstract class PgpEncryptedData
    {
		internal class TruncatedStream
			: BaseInputStream
		{
			private const int LookAheadSize = 22;
			private const int LookAheadBufSize = 512;
			private const int LookAheadBufLimit = LookAheadBufSize - LookAheadSize;

			private readonly Stream inStr;
			private readonly byte[] lookAhead = new byte[LookAheadBufSize];
			private int bufStart, bufEnd;

			internal TruncatedStream(
				Stream inStr)
			{
				int numRead = Streams.ReadFully(inStr, lookAhead, 0, lookAhead.Length);

				if (numRead < LookAheadSize)
					throw new EndOfStreamException();

				this.inStr = inStr;
				this.bufStart = 0;
				this.bufEnd = numRead - LookAheadSize;
			}

			private int FillBuffer()
			{
				if (bufEnd < LookAheadBufLimit)
					return 0;

				Debug.Assert(bufStart == LookAheadBufLimit);
				Debug.Assert(bufEnd == LookAheadBufLimit);

				Array.Copy(lookAhead, LookAheadBufLimit, lookAhead, 0, LookAheadSize);
				bufEnd = Streams.ReadFully(inStr, lookAhead, LookAheadSize, LookAheadBufLimit);
				bufStart = 0;
				return bufEnd;
			}

			public override int ReadByte()
			{
				if (bufStart < bufEnd)
					return lookAhead[bufStart++];

				if (FillBuffer() < 1)
					return -1;

				return lookAhead[bufStart++];
			}

			public override int Read(byte[] buf, int off, int len)
			{
				int avail = bufEnd - bufStart;

				int pos = off;
				while (len > avail)
				{
					Array.Copy(lookAhead, bufStart, buf, pos, avail);

					bufStart += avail;
					pos += avail;
					len -= avail;

					if ((avail = FillBuffer()) < 1)
						return pos - off;
				}

				Array.Copy(lookAhead, bufStart, buf, pos, len);
				bufStart += len;

				return pos + len - off;;
			}

			internal byte[] GetLookAhead(int lookAheadSize = 0)
			{
                byte[] temp = null;
                if (lookAheadSize == 0)
                {
                    temp = new byte[LookAheadSize];
                    Array.Copy(lookAhead, bufStart, temp, 0, LookAheadSize);
                }
                else
                {
                    temp = new byte[lookAheadSize];
                    Array.Copy(lookAhead, bufStart, temp, 0, lookAheadSize);
                }
                
				
				return temp;
			}
		}

		internal InputStreamPacket	encData;
        internal Stream				encStream;
        internal TruncatedStream	truncStream;

		internal PgpEncryptedData(
            InputStreamPacket encData)
        {
            this.encData = encData;
        }

		/// <summary>Return the raw input stream for the data stream.</summary>
        public virtual Stream GetInputStream()
        {
            return encData.GetInputStream();
        }

		/// <summary>Return true if the message is integrity protected.</summary>
		/// <returns>True, if there is a modification detection code namespace associated
		/// with this stream.</returns>
        public bool IsIntegrityProtected()
        {
			return encData is SymmetricEncIntegrityPacket;
        }

		/// <summary>Note: This can only be called after the message has been read.</summary>
		/// <returns>True, if the message verifies, false otherwise</returns>
        public bool Verify()
        {
            if (!IsIntegrityProtected())
                throw new PgpException("data not integrity protected.");

			DigestStream dIn = (DigestStream) encStream;

			//
            // make sure we are at the end.
            //
            while (encStream.ReadByte() >= 0)
            {
				// do nothing
            }

			//
            // process the MDC packet
            //
			byte[] lookAhead = truncStream.GetLookAhead();

            /*Console.WriteLine("\nLookahead: ");
            foreach (byte b in lookAhead)
                Console.Write(b + ", ");*/

			IDigest hash = dIn.ReadDigest();
			hash.BlockUpdate(lookAhead, 0, 2);
			byte[] digest = DigestUtilities.DoFinal(hash);

            /*Console.WriteLine("\ndigest: ");
            foreach (byte b in digest)
                Console.Write(b + ", ");*/

			byte[] streamDigest = new byte[digest.Length];
			Array.Copy(lookAhead, 2, streamDigest, 0, streamDigest.Length);

            /*Console.WriteLine("\nstreamDigest: ");
            foreach(byte b in streamDigest)
                Console.Write(b + ", ");
            Console.WriteLine("\nLookahead: ");
            foreach (byte b in lookAhead)
                Console.Write(b + ", ");*/

			return Arrays.ConstantTimeAreEqual(digest, streamDigest);
        }
    }
}
