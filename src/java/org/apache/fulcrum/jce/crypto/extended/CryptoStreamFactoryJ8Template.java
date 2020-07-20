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
public abstract class CryptoStreamFactoryJ8Template /*  extends CryptoStreamFactoryImpl*/ implements CryptoStreamFactoryJ8
{
	
	/** the salt for the algorithm */
    protected byte[] salt;

    /** the count paramter for the algorithm */
    protected int count;

    /** the name of the JCE provider */
    protected String providerName;

    /** the algorithm to use */
    protected String algorithm;
    
    /**
     * The JCE provider name known to work. If the value
     * is set to null an appropriate provider will be
     * used.
     */
    protected static final String PROVIDERNAME = null;

    protected static final int SALT_SIZE = 16; //might increase cipher length
    protected static final int KEY_SIZE = 256;

    /** the default instances */
    protected static Map<TYPES,CryptoStreamFactoryJ8Template> instances = new ConcurrentHashMap<>();
    
    //protected AlgorithmParameters algorithmParameters;// used only for debugging
   
    public CryptoStreamFactoryJ8Template() {
       
    }

    /**
     * Factory method to get a default instance
     * 
     * @param type the @see {@link TYPES} of the instance.
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
     * @param type {@link TYPES} what type the algorithm will be
     */
    public CryptoStreamFactoryJ8Template( byte[] salt, int count, TYPES type)
    {
        this.salt = salt.clone();
        this.count = count;
        this.providerName = PROVIDERNAME;
        this.algorithm = type.equals(TYPES.PBE)? CryptoParametersJ8.TYPES_IMPL.ALGORITHM_J8_PBE.getAlgorithm():
            CryptoParametersJ8.TYPES_IMPL.ALGORITHM_J8_GCM.getAlgorithm();;
    }


    /**
     * @see org.apache.fulcrum.jce.crypto.CryptoStreamFactory#getSmartInputStream(java.io.InputStream)
     */

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
    public InputStream getInputStream( InputStream is, char[] password )
        throws GeneralSecurityException, IOException
    {
        byte[] decrypted =  this.createCipher( is, Cipher.DECRYPT_MODE, password.clone() );
        InputStream eis = new ByteArrayInputStream(decrypted);
        return eis;
    }

    public OutputStream getOutputStream(InputStream is, OutputStream os, char[] password)
            throws GeneralSecurityException, IOException {
        byte[] encrypted =  this.createCipher( is, Cipher.ENCRYPT_MODE, password.clone() );
        InputStream eis = new ByteArrayInputStream(encrypted);
        StreamUtil.copy(eis, os);
        return os;
    }
    
    /**
     * resets the default instances
     */
    public static void resetInstances()
    {
        CryptoStreamFactoryJ8Template.instances.clear();
    }
    
    /**
     * Set the default instances from an external application.
     * @param instances the new default instances map
     * @throws Exception if instances are null
     */
    public static void setInstances(Map<TYPES,CryptoStreamFactoryJ8Template> instances ) throws Exception
    {
    	if (instances == null) throw new Exception("setting instances to null not allowed!");
        CryptoStreamFactoryJ8Template.instances = instances;
    }
    
    /** not used / implemented methods **/
    
    @Override
	public InputStream getInputStream(InputStream is, String decryptionMode)
			throws GeneralSecurityException, IOException {
		throw new UnsupportedOperationException("not implemented");
	}

	@Override
	public InputStream getInputStream(InputStream is, String decryptionMode, char[] password)
			throws GeneralSecurityException, IOException {
		throw new UnsupportedOperationException("not implemented");
	}

	@Override
	public InputStream getInputStream(InputStream is) throws GeneralSecurityException, IOException {
		throw new UnsupportedOperationException("not implemented");
	}

	@Override
	public InputStream getSmartInputStream(InputStream is, char[] password)
			throws GeneralSecurityException, IOException {
		throw new UnsupportedOperationException("not implemented");
	}

	@Override
	public OutputStream getOutputStream(OutputStream os) throws GeneralSecurityException, IOException {
		throw new UnsupportedOperationException("not implemented");
	}

	@Override
	public OutputStream getOutputStream(OutputStream os, char[] password) throws GeneralSecurityException, IOException {
		throw new UnsupportedOperationException("not implemented");
	}
    /** not used methods end **/

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
     * @param is the input stream
     * @param mode the cipher mode
     * @param password the password
     * @return an instance of a cipher
     * @return the cipher as byte array
     * @throws GeneralSecurityException creating a cipher failed
     * @throws IOException creating a cipher failed
     */
    protected abstract byte[] createCipher(InputStream is, int mode, char[] password )
        throws GeneralSecurityException, IOException;
    
    /**
     * creates salt from {@link SecureRandom#getInstance(String)} by default was algorithm SHA1PRNG
     * 
     * changed to {@link SecureRandom#getInstanceStrong()} and let the system decide, what PRNG to use for salt random.
     * 
     * salt size by default @link {@value #SALT_SIZE}.
     * 
     * @return the generated salt as byte array
     * @throws GeneralSecurityException if no algo could be found.
     */
    protected byte[] generateSalt() throws GeneralSecurityException {
        SecureRandom random;
        try {
            random = SecureRandom.getInstanceStrong();
            byte[] salt = new byte[SALT_SIZE ];
            random.nextBytes(salt);
            return salt;
        } catch (NoSuchAlgorithmException e) {
            throw new GeneralSecurityException(e);  
        }
    }

	public byte[] getSalt() {
		return salt.clone();
	}

	public void setSalt(byte[] salt) {
		this.salt = salt.clone();
	}

	public int getCount() {
		return count;
	}

	public void setCount(int count) {
		this.count = count;
	}

	public String getProviderName() {
		return providerName;
	}

	public void setProviderName(String providerName) {
		this.providerName = providerName;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

}
