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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Concrete factory for creating encrypting/decrypting streams. The
 * implementation uses the JCA (Java Crypto Extension) supplied
 * by SUN (using SunJCE 1.42).
 *
 * The implementation uses as PBEWithMD5AndDES for encryption which
 * should be sufficent for most applications.
 *
 * The implementation also supplies a default password in the case that
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

public final class CryptoStreamFactoryImpl implements CryptoStreamFactory
{
    /** the salt for the PBE algorithm */
    private byte[] salt;

    /** the count paramter for the PBE algorithm */
    private int count;

    /** the name of the JCE provider */
    private String providerName;

    /** the algorithm to use */
    private String algorithm;

    /** the default instance */
    private static CryptoStreamFactory instance;

    /**
     * The JCE provider name known to work. If the value
     * is set to null an appropriate provider will be
     * used.
     */
    private static final String PROVIDERNAME = null;

    /**
     * Factory method to get a default instance
     * @return an instance of the CryptoStreamFactory
     */
    public synchronized static CryptoStreamFactory getInstance()
    {
        if( CryptoStreamFactoryImpl.instance == null )
        {
            CryptoStreamFactoryImpl.instance = new CryptoStreamFactoryImpl();
        }

        return CryptoStreamFactoryImpl.instance;
    }

    /**
     * Set the default instance from an external application.
     * @param instance the new default instance
     */
    public static void setInstance( CryptoStreamFactory instance )
    {
        CryptoStreamFactoryImpl.instance = instance;
    }

    /**
     * Constructor
     */
    public CryptoStreamFactoryImpl()
    {
        this.salt = CryptoParameters.SALT;
        this.count = CryptoParameters.COUNT;
        this.providerName = PROVIDERNAME;
        this.algorithm = CryptoParameters.ALGORITHM;
    }

    /**
     * Constructor
     *
     * @param salt the salt for the PBE algorithm
     * @param count the iteration for PBEParameterSpec
     */
    public CryptoStreamFactoryImpl( byte[] salt, int count)
    {
        this.salt = salt;
        this.count = count;
        this.providerName = PROVIDERNAME;
        this.algorithm = CryptoParameters.ALGORITHM;
    }


    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getInputStream(java.io.InputStream, String)
     */
    public InputStream getInputStream(InputStream is, String decryptionMode) throws GeneralSecurityException, IOException {

        InputStream result = null;

        if( "auto".equalsIgnoreCase(decryptionMode) )
        {
            result = CryptoStreamFactoryImpl.getInstance().getSmartInputStream(is);
        }
        else if( "true".equalsIgnoreCase(decryptionMode) )
        {
            result = CryptoStreamFactoryImpl.getInstance().getInputStream(is);
        }
        else
        {
            result = is;
        }
        return result;
    }

    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getInputStream(java.io.InputStream, String, char[])
     */
    public InputStream getInputStream(InputStream is, String decryptionMode, char[] password) throws GeneralSecurityException, IOException {

        InputStream result = null;

        if( "auto".equalsIgnoreCase(decryptionMode) )
        {
            result = CryptoStreamFactoryImpl.getInstance().getSmartInputStream(is, password);
        }
        else if( "true".equalsIgnoreCase(decryptionMode) )
        {
            result = CryptoStreamFactoryImpl.getInstance().getInputStream(is, password);
        }
        else
        {
            result = is;
        }
        return result;
    }

    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getInputStream(java.io.InputStream)
     */
    public InputStream getInputStream( InputStream is )
        throws GeneralSecurityException, IOException
    {
        Cipher cipher = this.createCipher( Cipher.DECRYPT_MODE, PasswordFactory.create() );
        return new CipherInputStream( is, cipher );
    }

    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getInputStream(java.io.InputStream,char[])
     */
    public InputStream getInputStream( InputStream is, char[] password )
        throws GeneralSecurityException, IOException
    {
        Cipher cipher = this.createCipher( Cipher.DECRYPT_MODE, password );
        return new CipherInputStream( is, cipher );
    }

    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getSmartInputStream(java.io.InputStream)
     */
    public InputStream getSmartInputStream(InputStream is)
        throws GeneralSecurityException, IOException
    {
        return this.getSmartInputStream(
            is,
            PasswordFactory.create()
            );
    }

    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getSmartInputStream(java.io.InputStream,char[])
     */
    public InputStream getSmartInputStream(InputStream is, char[] password )
        throws GeneralSecurityException, IOException
    {
        SmartDecryptingInputStream result;

        result = new SmartDecryptingInputStream(
            getInstance(),
            is,
            password
            );

        return result;
    }

    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getOutputStream(java.io.OutputStream)
     */
    public OutputStream getOutputStream( OutputStream os )
        throws GeneralSecurityException, IOException
    {
        Cipher cipher = this.createCipher( Cipher.ENCRYPT_MODE, PasswordFactory.create() );
        return new CipherOutputStream( os, cipher );    }

    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getOutputStream(java.io.OutputStream, char[])
     */
    public OutputStream getOutputStream( OutputStream os, char[] password )
        throws GeneralSecurityException, IOException
    {
        Cipher cipher = this.createCipher( Cipher.ENCRYPT_MODE, password );
        return new CipherOutputStream( os, cipher );
    }

    /**
     * @return Returns the algorithm.
     */
    private String getAlgorithm()
    {
        return algorithm;
    }

    /**
     * @return Returns the count.
     */
    private int getCount()
    {
        return count;
    }

    /**
     * @return Returns the providerName.
     */
    private String getProviderName()
    {
        return providerName;
    }

    /**
     * @return Returns the salt.
     */
    private byte [] getSalt()
    {
        return salt;
    }

    /**
     * Create a PBE key.
     *
     * @param password the password to use.
     * @return the key
     * @throws GeneralSecurityException creating the key failed
     */
    private Key createKey( char[] password )
        throws GeneralSecurityException
    {
        SecretKeyFactory keyFactory;
        String algorithm = this.getAlgorithm();
        PBEKeySpec keySpec =  new PBEKeySpec(password);

        if( this.getProviderName() == null )
        {
            keyFactory = SecretKeyFactory.getInstance( algorithm );
        }
        else
        {
            keyFactory = SecretKeyFactory.getInstance( algorithm, this.getProviderName() );
        }

        return keyFactory.generateSecret(keySpec);
    }

    /**
     * Create a Cipher.
     *
     * @param mode the cipher mode
     * @param password the password
     * @return an instance of a cipher
     * @throws GeneralSecurityException creating a cipher failed
     * @throws IOException creating a cipher failed
     */
    private Cipher createCipher( int mode, char[] password )
        throws GeneralSecurityException, IOException
    {
        Cipher cipher;
        PBEParameterSpec paramSpec = new PBEParameterSpec( this.getSalt(), this.getCount() );
        Key key = this.createKey( password );

        if( this.getProviderName() == null )
        {
            cipher = Cipher.getInstance( this.getAlgorithm() );
        }
        else
        {
            cipher = Cipher.getInstance( this.getAlgorithm(), this.getProviderName() );
        }

        cipher.init( mode, key, paramSpec );
        return cipher;
    }
}
