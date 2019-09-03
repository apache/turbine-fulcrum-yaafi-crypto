package org.apache.fulcrum.jce.crypto.extended;

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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;

import org.apache.fulcrum.jce.crypto.CryptoStreamFactoryImpl;
import org.apache.fulcrum.jce.crypto.PasswordFactory;
import org.apache.fulcrum.jce.crypto.StreamUtil;
import org.apache.fulcrum.jce.crypto.algo.CryptoStreamGCMImpl;
import org.apache.fulcrum.jce.crypto.algo.CryptoStreamPBEImpl;
import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8.TYPES;

/**
 * Concrete factory for creating encrypting/decrypting streams. 
 * 
 * 
 **/
public abstract class CryptoStreamFactoryJ8Template extends CryptoStreamFactoryImpl implements CryptoStreamFactoryJ8
{

    protected static final int SALT_SIZE = 16; //might increase cipher length
    protected static final int KEY_SIZE = 256;

    /** the default instances */
    protected static Map<TYPES,CryptoStreamFactoryJ8Template> instances = new ConcurrentHashMap();
    
    protected AlgorithmParameters algorithmParameters;// used only for debugging
   
    public CryptoStreamFactoryJ8Template() {
       
    }

    /**
     * Factory method to get a default instance
     * @return an instance of the CryptoStreamFactory
     */
    public static CryptoStreamFactoryJ8 getInstance(TYPES type) 
    {
        synchronized (CryptoStreamFactoryJ8Template.class) {
            if( !instances.containsKey(type) )
            {
                try {
                    instances.put(type, 
                            (type.equals(TYPES.PBE))? new CryptoStreamPBEImpl():
                                new CryptoStreamGCMImpl()
                            );
                } catch (GeneralSecurityException e) {
                    e.printStackTrace();
                    throw new RuntimeException(e.getMessage());
                }
            }
    
            return instances.get(type);
        }
    }


    /**
     * Constructor
     *
     * @param salt the salt for the PBE algorithm
     * @param count the iteration for PBEParameterSpec
     * @paramn type {@link TYPES}
     */
    public CryptoStreamFactoryJ8Template( byte[] salt, int count, TYPES type)
    {
        this.salt = salt;
        this.count = count;
        this.providerName = PROVIDERNAME;
        this.algorithm = type.equals(TYPES.PBE)? CryptoParametersJ8.ALGORITHM_J8_PBE:
            CryptoParametersJ8.ALGORITHM_J8_GCM;
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
    protected abstract Key createKey( char[] password, byte[] salt ) 
            throws GeneralSecurityException;

    /**
     * Create a Cipher.
     *
     * @param mode the cipher mode
     * @param password the password
     * @return an instance of a cipher
     * @throws GeneralSecurityException creating a cipher failed
     * @throws IOException creating a cipher failed
     */
    protected abstract byte[] createCipher(InputStream is, int mode, char[] password )
        throws GeneralSecurityException, IOException;
    
    protected byte[] generateSalt() throws GeneralSecurityException {
        SecureRandom random;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
            byte[] salt = new byte[SALT_SIZE ];
            random.nextBytes(salt);
            return salt;
        } catch (NoSuchAlgorithmException e) {
            throw new GeneralSecurityException(e);  
        }
    }

}
