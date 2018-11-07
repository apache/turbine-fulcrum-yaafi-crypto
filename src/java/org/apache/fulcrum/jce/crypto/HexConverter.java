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
 * @author <a href="mailto:painter@apache.org">Jeffery Painter</a>
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl</a>
 * @author <a href="mailto:maakus@earthlink.net">Markus Hahn</a>
 */

public final class HexConverter
{
    /**
     * Converts a byte array to a hex string.
     *
     * @param data the byte array
     * @return the hex string
     */
    public static String toString( byte[] data )
    {
        return bytesToHexStr(data);
    }

    /**
     * Converts a hex string into a byte[]
     *
     * @param sHex the hex string
     * @return the byte[]
     */
    public static byte[] toBytes(String sHex) {
        int len = sHex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(sHex.charAt(i), 16) << 4)
                                 + Character.digit(sHex.charAt(i+1), 16));
        }
        return data;
    }    
    
    /**
     * Converts a byte array to a hex string.
     * @param data the byte array
     * @return the hex string
     */
    private static String bytesToHexStr( byte[] data )
    {
        StringBuilder sbuf = new StringBuilder();
        for ( byte b : data )
        	sbuf.append( String.format("%02x", b ) );
        return sbuf.toString();
    }

}
