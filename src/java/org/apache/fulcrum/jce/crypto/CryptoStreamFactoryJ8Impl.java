package org.apache.fulcrum.jce.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 *  * to you under the Apache License, Version 2.0 (the
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
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Concrete factory for creating encrypting/decrypting streams. The
 * implementation uses the JCA (Java Crypto Extension) supplied
 * by SUN (using SunJCE 1.42).
 *
 * The implementation uses as PBEWithHmacSHA256AndAES_128 for encryption which
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
 * @author <a href="mailto:gk@apache.org">Georg Kallidis</a>
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl </a>
 * @author <a href="mailto:maakus@earthlink.net">Markus Hahn</a>
 */

public final class CryptoStreamFactoryJ8Impl extends CryptoStreamFactoryImpl implements CryptoStreamFactoryJ8
{

    private static final int salt_size = 128;
    private static final int key_size = 128;

    /** the default instance */
    private static CryptoStreamFactoryJ8 instance;
    
    private AlgorithmParameters algorithmParameters;// used only for debugging 
    
    /**
     * Factory method to get a default instance
     * @return an instance of the CryptoStreamFactory
     */
    public synchronized static CryptoStreamFactoryJ8 getInstance() 
    {
        if( CryptoStreamFactoryJ8Impl.instance == null )
        {
            try {
                CryptoStreamFactoryJ8Impl.instance = new CryptoStreamFactoryJ8Impl();
            } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        }

        return CryptoStreamFactoryJ8Impl.instance;
    }

    /**
     * Set the default instance from an external application.
     * @param instance the new default instance
     */
    public static void setInstance( CryptoStreamFactoryJ8 instance )
    {
        CryptoStreamFactoryJ8Impl.instance = instance;
    }

    /**
     * Constructor
     */
    public CryptoStreamFactoryJ8Impl() throws GeneralSecurityException
    {
        this.salt =  generateSalt();
        this.count = CryptoParameters.COUNT_J8;
        this.providerName = PROVIDERNAME;
        this.algorithm = CryptoParameters.ALGORITHM_J8;
    }
    
    /**
     * Constructor
     */
    public CryptoStreamFactoryJ8Impl(String algo) throws GeneralSecurityException
    {
        this.salt =  generateSalt();
        this.count = CryptoParameters.COUNT_J8;
        this.providerName = PROVIDERNAME;
        this.algorithm = algo;
    }

    /**
     * Constructor
     *
     * @param salt the salt for the PBE algorithm
     * @param count the iteration for PBEParameterSpec
     */
    public CryptoStreamFactoryJ8Impl( byte[] salt, int count)
    {
        this.salt = salt;
        this.count = count;
        this.providerName = PROVIDERNAME;
        this.algorithm = CryptoParameters.ALGORITHM_J8;
    }


    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getSmartInputStream(java.io.InputStream)
     */
    @Override
    public InputStream getSmartInputStream(InputStream is)
        throws GeneralSecurityException, IOException
    {
        return this.getSmartInputStream(
            is,
            PasswordFactory.getInstance("SHA-256").create()
            );
    }

    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getInputStream(java.io.InputStream,char[])
     */
    @Override
    public InputStream getInputStream( InputStream is, char[] password )
        throws GeneralSecurityException, IOException
    {
        byte[] encrypted =  this.createCipher( is, Cipher.DECRYPT_MODE, password );
        InputStream eis = new ByteArrayInputStream(encrypted);
        return eis;
    }

    
    @Override
    public OutputStream getOutputStream(InputStream is, OutputStream os, char[] password)
            throws GeneralSecurityException, IOException {
        byte[] encrypted =  this.createCipher( is, Cipher.ENCRYPT_MODE, password );
        InputStream eis = new ByteArrayInputStream(encrypted);
        StreamUtil.copy(eis, os);
        return os;
    }

    /**
     * Create a PBE key.
     *
     * @param password the password to use.
     * @param salt if provided this is used, otherweise {@link #getSalt()}.
     * @return the key
     * @throws GeneralSecurityException creating the key failed
     */
    private Key createKey( char[] password, byte[] salt ) 
            throws GeneralSecurityException
    {
        SecretKeyFactory keyFactory;
        String algorithm = this.getAlgorithm();
        
        PBEKeySpec keySpec = new PBEKeySpec(password, (salt == null)? this.getSalt(): salt, this.getCount(), key_size );
        byte[] encodedTmp = null;
        try {
            if( this.getProviderName() == null )
            {
                keyFactory = SecretKeyFactory.getInstance( algorithm );
            }
            else
            {
                keyFactory = SecretKeyFactory.getInstance( algorithm, this.getProviderName() );
            }
            return keyFactory.generateSecret(keySpec);
            
        } catch (NoSuchAlgorithmException e) {
            throw new GeneralSecurityException(e);
        } finally {
            if (encodedTmp != null) {
                Arrays.fill(encodedTmp, (byte)0); 
            }
            if (keySpec != null) {
                keySpec.clearPassword();
            }
        }
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
    private byte[] createCipher(InputStream is, int mode, char[] password )
        throws GeneralSecurityException, IOException
    {
        Cipher cipher;
        PBEParameterSpec paramSpec = null; 
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream(1024);
        long total = StreamUtil.copy(is, bos);
        byte[] input = bos.toByteArray();
        
        byte[] ciphertext = null;
        
        byte[] salt = null;
        byte[] iv = null;
        if (mode == Cipher.DECRYPT_MODE) {
            salt = Arrays.copyOfRange(input, 0, salt_size / 8);
            iv = Arrays.copyOfRange(input, salt.length, salt.length + 128 / 8);
            ciphertext = Arrays.copyOfRange(input, salt.length + iv.length, input.length);// cut out salt and iv
        }
        
        Key key = this.createKey( password, salt );
        
        if( this.getProviderName() == null )
        {
            cipher = Cipher.getInstance( this.getAlgorithm() );
        }
        else
        {
            cipher = Cipher.getInstance( this.getAlgorithm(), this.getProviderName() );
        }
        
        // save
        if (mode == Cipher.DECRYPT_MODE) {             
            paramSpec = new PBEParameterSpec( salt, this.getCount(), new IvParameterSpec(iv) );
            cipher.init( mode, key, paramSpec );
            //cipher.init( mode, key, algorithmParameters );
            ciphertext = cipher.doFinal(ciphertext);
        }
        
        // save
        if (mode == Cipher.ENCRYPT_MODE) {        
            paramSpec = new PBEParameterSpec( this.getSalt(), this.getCount() );
            salt = paramSpec.getSalt();
            cipher.init( mode, key, paramSpec );   
            //algorithmParameters = cipher.getParameters();
            
            byte[] result = cipher.doFinal(input);
            iv = cipher.getIV(); 
            
            // Salt and IV need to be stored with the result, otherwise we can't decrypt the message later.
            ciphertext = new byte[salt.length + iv.length + result.length];
            System.arraycopy(salt, 0, ciphertext, 0, salt.length);
            System.arraycopy(iv, 0, ciphertext, salt.length, iv.length);
            System.arraycopy(result, 0, ciphertext, salt.length + iv.length, result.length);// push after salt and iv  
        }
        return ciphertext;
    }
    
    private byte[] generateSalt() throws GeneralSecurityException {
        SecureRandom random;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
            byte[] salt = new byte[salt_size / 8];
            random.nextBytes(salt);
            return salt;
        } catch (NoSuchAlgorithmException e) {
            throw new GeneralSecurityException(e);  
        }

    }

}
