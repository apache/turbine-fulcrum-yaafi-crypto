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
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.fulcrum.jce.crypto.StreamUtil;
import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8;
import org.apache.fulcrum.jce.crypto.extended.CryptoStreamFactoryJ8Template;

/**
 * Concrete implementation for creating encrypting/decrypting streams. The
 * implementation uses the JCA (Java Crypto Extension) supplied
 * by SUN (using SunJCE 1.42).
 *
 * The implementation uses as @see {@link CryptoParametersJ8#ALGORITHM_J8_PBE} for encryption which
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

public final class CryptoStreamPBEImpl extends CryptoStreamFactoryJ8Template
{

    protected static final int IV_SIZE = 16;
    /**
     * Constructor
     */
    public CryptoStreamPBEImpl() throws GeneralSecurityException
    {
        this.salt =  generateSalt();
        this.count = CryptoParametersJ8.COUNT_J8;
        this.providerName = PROVIDERNAME;
        this.algorithm = CryptoParametersJ8.TYPES_IMPL.ALGORITHM_J8_PBE.getAlgorithm();
    }
    
    /**
     * Constructor
     *
     * @param salt the salt for the PBE algorithm
     * @param count the iteration for PBEParameterSpec
     */
    public CryptoStreamPBEImpl( byte[] salt, int count) throws GeneralSecurityException
    {
        this.salt = salt;
        this.count = count;
        this.providerName = PROVIDERNAME;
        this.algorithm = CryptoParametersJ8.TYPES_IMPL.ALGORITHM_J8_PBE.getAlgorithm();
    }

    /**
     * Create a PBE key.
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
        SecretKeyFactory keyFactory;
        String algorithm = this.getAlgorithm();
        
        PBEKeySpec keySpec = new PBEKeySpec(password, (salt == null)? this.getSalt(): salt, this.getCount(), KEY_SIZE );

        byte[] encodedTmp = null;
        try {
            if( getProviderName() == null )
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
    @Override
    protected byte[] createCipher(InputStream is, int mode, char[] password )
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
            
            ByteBuffer byteBuffer = ByteBuffer.wrap(input);
            salt = new byte[SALT_SIZE ];
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
           
            paramSpec = new PBEParameterSpec( salt, this.getCount(), new IvParameterSpec(iv) );
     
            cipher.init( mode, key, paramSpec );
            //cipher.init( mode, key, algorithmParameters );
            ciphertext = cipher.doFinal(ciphertext); // actually the unencrypted bytes
        }
        
        // save
        if (mode == Cipher.ENCRYPT_MODE) {        
            paramSpec = new PBEParameterSpec( this.getSalt(), this.getCount() );
            salt = paramSpec.getSalt();
            cipher.init( mode, key, paramSpec );   
            //algorithmParameters = cipher.getParameters();
 
            byte[] result = cipher.doFinal(input);
            iv = cipher.getIV(); // AES has 128bit block size, but iv is 16bit 
           
            // Salt and IV need to be stored with the result, otherwise we can't decrypt the message later.
            ByteBuffer byteBuffer = ByteBuffer.allocate(salt.length + iv.length + result.length);
            ciphertext = byteBuffer.put(salt).put(iv).put(result).array();
            
//            ciphertext = new byte[salt.length + iv.length + result.length];         
//            System.arraycopy(salt, 0, ciphertext, 0, salt.length);
//            System.arraycopy(iv, 0, ciphertext, salt.length, iv.length);
//            System.arraycopy(result, 0, ciphertext, salt.length + iv.length, result.length);// push after salt and iv  
        }
        return ciphertext;
    }


    @Override
    protected Cipher createCipher(int encryptMode, char[] password) throws GeneralSecurityException, IOException {
        throw new RuntimeException("not provided for this implementation");
    }

}
