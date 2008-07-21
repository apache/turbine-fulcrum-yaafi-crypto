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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 * Helper class to provde generic functions to work with CryptoStreams.
 *
 * The code uses parts from Markus Hahn's Blowfish library found at
 * http://blowfishj.sourceforge.net/
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl </a>
 * @author <a href="mailto:maakus@earthlink.net">Markus Hahn</a>
 */

public final class CryptoUtil
{
    /** the size of the internal buffer to copy streams */
    private static final int BUFFER_SIZE = 1024;

    /**
     * Copies from a source to a target object using encryption
     *
     * @param source the source object
     * @param target the target object
     * @param password the password to use for encryption
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException accessing the souce failed
     *
     */
    public static void encrypt( Object source, Object target, char[] password )
        throws GeneralSecurityException, IOException
    {
        CryptoUtil.encrypt(
            CryptoUtil.getCryptoStreamFactory(),
            source,
            target,
            password
            );
    }

    /**
     * Copies from a source to a target object using encryption and a
     * caller supplied CryptoStreamFactory.
     *
     * @param factory the factory to create the crypto streams
     * @param source the source object
     * @param target the target object
     * @param password the password to use for encryption
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException accessing the souce failed
     */
    public static void encrypt(
        CryptoStreamFactory factory, Object source, Object target, char[] password )
        throws GeneralSecurityException, IOException
    {
        InputStream is = CryptoUtil.createInputStream( source );
        OutputStream os = CryptoUtil.createOutputStream( target );
        OutputStream eos = factory.getOutputStream( os, password );
        CryptoUtil.copy( is, eos );
    }

    /**
     * Copies from a source to a target object using decryption.
     *
     * @param source the source object
     * @param target the target object
     * @param password the password to use for decryption
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException accessing the souce failed
     */
    public static void decrypt( Object source, Object target, char[] password )
        throws GeneralSecurityException, IOException
    {
        CryptoUtil.decrypt(
            CryptoUtil.getCryptoStreamFactory(),
            source,
            target,
            password
            );
    }

    /**
     * Copies from a source to a target object using decryption and a
     * caller-suppier CryptoStreamFactory.
     *
     * @param factory the factory to create the crypto streams
     * @param source the source object
     * @param target the target object
     * @param password the password to use for decryption
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException accessing the souce failed
     */
    public static void decrypt(
        CryptoStreamFactory factory, Object source, Object target, char[] password )
        throws GeneralSecurityException, IOException
    {
        InputStream is = CryptoUtil.createInputStream( source );
        OutputStream os = CryptoUtil.createOutputStream( target );
        InputStream dis = factory.getInputStream( is, password );
        CryptoUtil.copy( dis, os );
    }

    /**
     * Encrypts a string into a hex string.
     *
     * @param plainText the plain text to be encrypted
     * @param password the password for encryption
     * @return the encrypted string
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException accessing the souce failed
     */
    public static String encryptString( String plainText, char[] password )
        throws GeneralSecurityException, IOException
    {
        return CryptoUtil.encryptString(
            CryptoUtil.getCryptoStreamFactory(),
            plainText,
            password
            );
    }

    /**
     * Encrypts a string into a hex string.
     *
     * @param factory the factory to create the crypto streams
     * @param plainText the plain text to be encrypted
     * @param password the password for encryption
     * @return the encrypted string
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException accessing the souce failed
     */
    public static String encryptString(
        CryptoStreamFactory factory, String plainText, char[] password )
        throws GeneralSecurityException, IOException
    {
        ByteArrayOutputStream bais = new ByteArrayOutputStream();
        CryptoUtil.encrypt( factory, plainText, bais, password );
        return HexConverter.toString( bais.toByteArray() );
    }

    /**
     * Decrypts an encrypted string into the plain text. The encrypted
     * string must be a hex string created by encryptString.
     *
     * @param cipherText the encrypted text to be decrypted
     * @param password the password for decryption
     * @return the decrypted string
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException accessing the souce failed
     */
    public static String decryptString( String cipherText, char[] password )
        throws GeneralSecurityException, IOException
    {
        return CryptoUtil.decryptString(
            CryptoUtil.getCryptoStreamFactory(),
            cipherText,
            password
            );
    }

    /**
     * Decrypts an encrypted string into the plain text. The encrypted
     * string must be a hex string created by encryptString.
     *
     * @param factory the factory to create the crypto streams
     * @param cipherText the encrypted text to be decrypted
     * @param password the password for decryption
     * @return the decrypted string
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException accessing the souce failed
     */
    public static String decryptString(
        CryptoStreamFactory factory, String cipherText, char[] password )
        throws GeneralSecurityException, IOException
    {
        byte[] buffer = HexConverter.toBytes( cipherText );
        ByteArrayOutputStream bais = new ByteArrayOutputStream();
        CryptoUtil.decrypt( factory, buffer, bais, password );
        return new String( bais.toByteArray(), "utf-8" );
    }

    ///////////////////////////////////////////////////////////////////////////
    // Private Implementation
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Create an input stream supporting the following types
     *
     * <ul>
     *  <li>String</li>
     *  <li>File</li>
     *  <li>byte[]</li>
     *  <li>char[]</li>
     *  <li>ByteArrayOutputStream</li>
     *  <li>InputStream</li>
     * </ul>
     *
     * @param source the source object
     * @return the created input stream
     * @throws IOException creating the input stream failed
     */
    private static InputStream createInputStream( Object source )
        throws IOException
    {
        InputStream is;

        // create an InputStream

        if( source instanceof String )
        {
            byte[] content = ((String) source).getBytes("utf-8");
            is = new ByteArrayInputStream( content );
        }
        else if( source instanceof File )
        {
            is = new FileInputStream( (File) source );
        }
        else if( source instanceof byte[] )
        {
            is = new ByteArrayInputStream( (byte[]) source );
        }
        else if( source instanceof char[] )
        {
            byte[] content = new String((char[])source).getBytes("utf-8");
            is = new ByteArrayInputStream( content );
        }
        else if( source instanceof ByteArrayOutputStream )
        {
            byte[] content = ((ByteArrayOutputStream) source).toByteArray();
            is = new ByteArrayInputStream( content );
        }
        else
        {
            is = (InputStream) source;
        }

        return is;
    }

    /**
     * Create an output stream supporting the following types
     *
     * <ul>
     *  <li>File</li>
     *  <li>OutputStream</li>
     * </ul>
     *
     * @param target the target object
     * @return the output stream
     * @throws IOException creating the output stream failed
     */
    private static OutputStream createOutputStream( Object target )
        throws IOException
    {
        OutputStream os;

        if( target instanceof File )
        {
            os = new FileOutputStream( (File) target );
        }
        else
        {
            os = (OutputStream) target;
        }

        return os;
    }

    /**
     * Pumps the input stream to the output stream.
     *
     * @param is the source input stream
     * @param os the target output stream
     * @return the number of bytes copied
     * @throws IOException the copying failed
     */
    public static long copy( InputStream is, OutputStream os )
        throws IOException
    {
        byte[] buf = new byte[BUFFER_SIZE];
        int n = 0;
        long total = 0;

        while ((n = is.read(buf)) > 0)
        {
            os.write(buf, 0, n);
            total += n;
        }

        is.close();

        os.flush();
        os.close();

        return total;
    }

    /**
     * @return the CryptoStreamFactory to be used
     */
    public static CryptoStreamFactory getCryptoStreamFactory()
    {
        return CryptoStreamFactoryImpl.getInstance();
    }
}
