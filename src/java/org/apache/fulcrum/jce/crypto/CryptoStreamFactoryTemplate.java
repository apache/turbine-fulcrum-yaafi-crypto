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

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

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

public abstract class CryptoStreamFactoryTemplate implements CryptoStreamFactory
{

    /** the default instance */
    protected static CryptoStreamFactory instance;
    
    public static CryptoStreamFactory getInstance() {
        return instance;
    }

    public static void setInstance(CryptoStreamFactory instance) {
        CryptoStreamFactoryTemplate.instance = instance;
    }

    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getInputStream(java.io.InputStream, String)
     */
    public InputStream getInputStream(InputStream is, String decryptionMode) throws GeneralSecurityException, IOException {

        InputStream result = null;

        if( "auto".equalsIgnoreCase(decryptionMode) )
        {
            result = getSmartInputStream(is);
        }
        else if( "true".equalsIgnoreCase(decryptionMode) )
        {
            result = getInputStream(is);
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
            result = getSmartInputStream(is, password);
        }
        else if( "true".equalsIgnoreCase(decryptionMode) )
        {
            result = getInputStream(is, password);
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
        Cipher cipher = this.createCipher( Cipher.DECRYPT_MODE, PasswordFactory.getInstance().create() );
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
            PasswordFactory.getInstance().create()
            );
    }

    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getSmartInputStream(java.io.InputStream,char[])
     */
    public abstract InputStream getSmartInputStream(InputStream is, char[] password )
        throws GeneralSecurityException, IOException;

    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getOutputStream(java.io.OutputStream)
     */
    public OutputStream getOutputStream( OutputStream os )
        throws GeneralSecurityException, IOException
    {
        Cipher cipher = this.createCipher( Cipher.ENCRYPT_MODE, PasswordFactory.getInstance().create() );
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
    protected abstract Cipher createCipher(int encryptMode, char[] password) throws GeneralSecurityException, IOException;

}
