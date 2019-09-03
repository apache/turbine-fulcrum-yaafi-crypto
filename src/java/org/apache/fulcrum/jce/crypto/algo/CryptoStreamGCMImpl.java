package org.apache.fulcrum.jce.crypto.algo;

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
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.fulcrum.jce.crypto.StreamUtil;
import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8;
import org.apache.fulcrum.jce.crypto.extended.CryptoStreamFactoryJ8Template;

/**
 * Concrete implementation for creating encrypting/decrypting streams. The
 * implementation uses the JCA (Java Crypto Extension) supplied
 * by SUN (using SunJCE 1.42).
 *
 * The implementation uses @see {@link CryptoParametersJ8#ALGORITHM_J8_GCM} for encryption which
 * should be sufficent for most applications.
 *
 * The implementation also supplies a default password in the case that
 * the programmer don't want to have additional hassles. It is easy to
 * reengineer the password being used but much better than a hard-coded
 * password in the application.
 *
 *
 * @author <a href="mailto:gk@apache.org">Georg Kallidis</a>
 */

public final class CryptoStreamGCMImpl extends CryptoStreamFactoryJ8Template
{  

    protected static final int IV_SIZE = 12;
    /**
     * Constructor
     */
    public CryptoStreamGCMImpl() throws GeneralSecurityException
    {
        this.salt =  generateSalt();
        this.count = CryptoParametersJ8.COUNT_J8;// not used
        this.providerName = PROVIDERNAME;
        this.algorithm = CryptoParametersJ8.ALGORITHM_J8_GCM;
    }


    /**
     * Constructor
     *
     * @param salt the salt for the PBE algorithm
     * @param count the iteration for PBEParameterSpec
     */
    public CryptoStreamGCMImpl( byte[] salt, int count) throws GeneralSecurityException
    {
        this.salt = salt;
        this.count = count;
        this.providerName = PROVIDERNAME;
        this.algorithm = CryptoParametersJ8.ALGORITHM_J8_GCM;
    }

    /**
     * Create a AES/GCM key.
     *
     * @param password the password to use.
     * @param salt if provided this is used, otherweise {@link #getSalt()}.
     * @return the key
     * @throws GeneralSecurityException creating the key failed
     */
    @Override
    protected Key createKey( char[] password, byte[] salt ) 
            throws GeneralSecurityException
    {

        SecretKey key = new SecretKeySpec(((salt == null)? this.getSalt(): salt), "AES"); 
        return key;
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
    @Override
    protected byte[] createCipher(InputStream is, int mode, char[] password )
        throws GeneralSecurityException, IOException
    {
        Cipher cipher;
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream(1024);
        long total = StreamUtil.copy(is, bos);
        byte[] input = bos.toByteArray();
        
        byte[] ciphertext = null;  
        byte[] salt = null;
        byte[] iv = null;
        
        if (mode == Cipher.DECRYPT_MODE) {   
            
            ByteBuffer byteBuffer = ByteBuffer.wrap(input);
            salt = new byte[ SALT_SIZE ];
            byteBuffer.get(salt);
            iv = new byte[ IV_SIZE ];
            byteBuffer.get(iv);
            ciphertext = new byte[byteBuffer.remaining()];
            byteBuffer.get(ciphertext);
            
//            salt = Arrays.copyOfRange(input, 0, SALT_SIZE );
//            iv = Arrays.copyOfRange(input, salt.length, salt.length + 16 );
//            ciphertext = Arrays.copyOfRange(input, salt.length + iv.length, input.length);// cut out salt and iv
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
            
            GCMParameterSpec gcmParamSpec = new GCMParameterSpec(128, iv);
            cipher.init( mode, key, gcmParamSpec );
            
            //cipher.init( mode, key, algorithmParameters );
            ciphertext = cipher.doFinal(ciphertext); // actually the unencrypted bytes
        }
        
        // save
        if (mode == Cipher.ENCRYPT_MODE) {        
            iv = generateIV();
            GCMParameterSpec gcmParamSpec = new GCMParameterSpec(128, iv);
            
            salt = this.getSalt();
            cipher.init( mode, key, gcmParamSpec );

            //algorithmParameters = cipher.getParameters();
            
            // might update with associated Data
            // cipher.updateAAD(associatedData );// not supported PBEWithHmacSHA256AndAES_256
            
            byte[] result = cipher.doFinal(input);
            //iv = cipher.getIV(); // AES has 128bit block size, but iv is 16bit 
           
            // Salt and IV need to be stored with the result, otherwise we can't decrypt the message later.
            ByteBuffer byteBuffer = ByteBuffer.allocate(salt.length + iv.length + result.length);
            ciphertext = byteBuffer.put(salt).put(iv).put(result).array();
            
//            ciphertext = new byte[salt.length + iv.length + result.length];
//            
//            System.arraycopy(salt, 0, ciphertext, 0, salt.length);
//            System.arraycopy(iv, 0, ciphertext, salt.length, iv.length);
//            System.arraycopy(result, 0, ciphertext, salt.length + iv.length, result.length);// push after salt and iv  
        }
        return ciphertext;
    }
    
    private byte[] generateIV( ) throws GeneralSecurityException {
        SecureRandom random;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
            byte[] iv = new byte[ IV_SIZE ];
            random.nextBytes(iv);
            return iv;
        } catch (NoSuchAlgorithmException e) {
            throw new GeneralSecurityException(e);  
        }
    }

    @Override
    protected Cipher createCipher(int encryptMode, char[] password) throws GeneralSecurityException, IOException {
        throw new RuntimeException("not provided for this implementation");
    }


}
