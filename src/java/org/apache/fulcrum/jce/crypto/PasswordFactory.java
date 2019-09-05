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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The implementation supplies a default password in the case that
 * the programmer don't want to have additional hassles. It is easy to
 * reengineer the password being used but much better than a hard-coded
 * password in the application.
 *
 * The code uses parts from Markus Hahn's Blowfish library found at
 * http://blowfishj.sourceforge.net/
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl </a>
 * @author <a href="mailto:maakus@earthlink.net">Markus Hahn</a>
 */

public class PasswordFactory implements PasswordParameters
{

    private static PasswordFactory instance;
    
    String algo;
    
    int count = PasswordParameters.COUNT;
    
    public PasswordFactory(String algo) {
       this.algo = algo;
    }
    
    public PasswordFactory(String algo, int count) {
        this.algo = algo;
        this.count = count;
     }
      
    /**
     * Factory method to get a default instance
     * @return an instance of the CryptoStreamFactory
     */
    public synchronized static PasswordFactory getInstance() 
    {
        if( PasswordFactory.instance == null )
        {
           PasswordFactory.instance = new PasswordFactory("SHA1");
        }

        return PasswordFactory.instance;
    }
    
    /**
     * Factory method to get a default instance
     * @return an instance of the CryptoStreamFactory
     */
    public synchronized static PasswordFactory getInstance(String algo) 
    {
        if( PasswordFactory.instance == null )
        {
           PasswordFactory.instance = new PasswordFactory(algo);
        }

        return PasswordFactory.instance;
    }
    
    /**
     * Factory method to get a default instance
     * @return an instance of the CryptoStreamFactory
     */
    public synchronized static PasswordFactory getInstance(String algo, int count) 
    {
        if( PasswordFactory.instance == null )
        {
           PasswordFactory.instance = new PasswordFactory(algo, count);
        }

        return PasswordFactory.instance;
    }
    
    /**
     * Create a new password
     * 
     * @return a default password using "xxxx-xxxx-xxxx-xxxxx"
     * 
     * @throws NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws UnsupportedEncodingException the requested encoding is not supported
     */
    public char[] create()
        throws NoSuchAlgorithmException, UnsupportedEncodingException
    {
        return create(
            PasswordParameters.DefaultPassword(),
            PasswordParameters.Salt(),
            count
            );
    }

    /**
     * Create a new password using a seed
     * 
     * @param seed the default password supplied by the caller
     * @return a password using "xxxx-xxxx-xxxx-xxxxx"
     * 
     * @throws NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws UnsupportedEncodingException the requested encoding is not supported
     */
    public char[] create( String seed )
        throws NoSuchAlgorithmException, UnsupportedEncodingException
    {
        return create(
            seed.toCharArray()
            );
    }

    /**
     * @param seed the default password supplied by the caller
     * @return a password using "xxxx-xxxx-xxxx-xxxxx"
     * @throws NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws UnsupportedEncodingException the requested encoding is not supported
     */
    public final char[] create( char[] seed )
        throws NoSuchAlgorithmException, UnsupportedEncodingException
    {
        return create(
            seed,
            PasswordParameters.Salt(),
            count
            );
    }

    /**
     * Creates a default password using "xxxx-xxxx-xxxx-xxxxx".
     *
     * @param salt the password salt
     * @param password the default password
     * @param count number of MessageDigest iterations
     * @return the default password
     * @throws NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws UnsupportedEncodingException the requested encoding is not supported
     */
    public char [] create( char[] password, byte[] salt, int count )
        throws NoSuchAlgorithmException, UnsupportedEncodingException
    {
        char [] result = null;
        MessageDigest sha1 = MessageDigest.getInstance( algo );
        byte [] passwordMask = new String( password ).getBytes( "UTF-8" );
        byte [] temp = new byte[salt.length + passwordMask.length];
        byte [] digest = null;

        StringBuilder stringBuffer = new StringBuilder();

        // combine the password with the salt string into a byte[9

        System.arraycopy( passwordMask, 0, temp, 0, passwordMask.length );
        System.arraycopy( salt, 0, temp, passwordMask.length, salt.length );

        // create a hash over and over to make it a bit random

        digest = temp;

        for (int i = 0; i < count; i++)
        {
            sha1.update( digest );
            digest = sha1.digest();
        }

        // build a well-formed password string to be usable
        // by a human

        long long1 = createLong( digest, 0 );
        long long2 = createLong( digest, 4 );
        long long3 = createLong( digest, 8 );
        long long4 = createLong( digest, 12 );

        stringBuffer.append( Long.toHexString( long1 ).substring( 0, 4 ) );
        stringBuffer.append( '-' );
        stringBuffer.append( Long.toHexString( long2 ).substring( 0, 4 ) );
        stringBuffer.append( '-' );
        stringBuffer.append( Long.toHexString( long3 ).substring( 0, 4 ) );
        stringBuffer.append( '-' );
        stringBuffer.append( Long.toHexString( long4 ).substring( 0, 5 ) );

        // copy the password
        result = new char[stringBuffer.length()];

        for (int i = 0; i < stringBuffer.length(); i++)
        {
            result[i] = stringBuffer.charAt( i );
        }

        // wipe out the StringBuilder
        for (int i = 0; i < stringBuffer.length(); i++)
        {
            stringBuffer.setCharAt( i, ' ' );
        }

        return result;
    }

    /**
     * Gets bytes from an array into a long.
     *
     * @param buf where to get the bytes
     * @param nOfs index from where to read the data
     * @return the 64bit integer
     */
    private static long createLong(byte [] buf, int nOfs)
    {
        return
            ((long)(( buf[nOfs    ]          << 24) |
                    ((buf[nOfs + 1] & 0x0ff) << 16) |
                    ((buf[nOfs + 2] & 0x0ff) <<  8) |
                    ( buf[nOfs + 3] & 0x0ff       )) << 32) |
            ((long)(( buf[nOfs + 4]          << 24) |
                    ((buf[nOfs + 5] & 0x0ff) << 16) |
                    ((buf[nOfs + 6] & 0x0ff) <<  8) |
                    ( buf[nOfs + 7] & 0x0ff       )) & 0x0ffffffffL);
    }
}
