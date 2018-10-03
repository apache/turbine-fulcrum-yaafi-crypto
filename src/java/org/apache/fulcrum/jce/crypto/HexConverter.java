package org.apache.fulcrum.jce.crypto;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */


/**
 * Helper class to for HEX conversion.
 *
 * The code uses parts from Markus Hahn's Blowfish library found at
 * http://blowfishj.sourceforge.net/
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl </a>
 * @author <a href="mailto:maakus@earthlink.net">Markus Hahn</a>
 */

public final class HexConverter
{
    /**
     * Table for byte to hex conversion
     */
    final private static char[] HEXTAB =
    {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    /**
     * Converts a byte array to a hex string.
     *
     * @param data the byte array
     * @return the hex string
     */
    public static String toString( byte[] data )
    {
        return bytesToHexStr(data, 0, data.length);
    }

    /**
     * Converts a hex string into a byte[]
     *
     * @param data the hex string
     * @return the byte[]
     */

    public static byte[] toBytes( String data )
    {
        byte[] result = new byte[data.length()/2];
        hexStrToBytes( data, result, 0, 0, result.length );
        return result;
    }

    /**
     * Converts a byte array to a hex string.
     * @param data the byte array
     * @param nOfs start index where to get the bytes
     * @param nLen number of bytes to convert
     * @return the hex string
     */
    private static String bytesToHexStr(
        byte[] data,
        int nOfs,
        int nLen)
    {
        StringBuilder sbuf;

        sbuf = new StringBuilder();
        sbuf.setLength(nLen << 1);

        int nPos = 0;
        int nC = nOfs + nLen;

        while (nOfs < nC)
        {
            sbuf.setCharAt(nPos++, HEXTAB[(data[nOfs  ] >> 4) & 0x0f]);
            sbuf.setCharAt(nPos++, HEXTAB[ data[nOfs++]       & 0x0f]);
        }

        return sbuf.toString();
    }

    /**
     * Converts a hex string back into a byte array (invalid codes will be
     * skipped).
     * @param sHex hex string
     * @param data the target array
     * @param nSrcOfs from which character in the string the conversion should
     * begin, remember that (nSrcPos modulo 2) should equals 0 normally
     * @param nDstOfs to store the bytes from which position in the array
     * @param nLen number of bytes to extract
     * @return number of extracted bytes
     */
    private static int hexStrToBytes(
        String sHex,
        byte[] data,
        int nSrcOfs,
        int nDstOfs,
        int nLen)
    {
        int nI, nJ, nStrLen, nAvailBytes, nDstOfsBak;
        byte bActByte;
        boolean blConvertOK;

        // check for correct ranges

        nStrLen = sHex.length();

        nAvailBytes = (nStrLen - nSrcOfs) >> 1;
        if (nAvailBytes < nLen)
        {
            nLen = nAvailBytes;
        }

        int nOutputCapacity = data.length - nDstOfs;
        if (nLen > nOutputCapacity)
        {
            nLen = nOutputCapacity;
        }

        // convert now

        nDstOfsBak = nDstOfs;

        for (nI = 0; nI < nLen; nI++)
        {
            bActByte = 0;
            blConvertOK = true;

            for (nJ = 0; nJ < 2; nJ++)
            {
                bActByte <<= 4;
                char cActChar = sHex.charAt(nSrcOfs++);

                if ((cActChar >= 'a') && (cActChar <= 'f'))
                {
                    bActByte |= (byte) (cActChar - 'a') + 10;
                }
                else
                {
                    if ((cActChar >= '0') && (cActChar <= '9'))
                    {
                        bActByte |= (byte) (cActChar - '0');
                    }
                    else
                    {
                        blConvertOK = false;
                    }
                }
            }
            if (blConvertOK)
            {
                data[nDstOfs++] = bActByte;
            }
        }

        return (nDstOfs - nDstOfsBak);
    }
}
