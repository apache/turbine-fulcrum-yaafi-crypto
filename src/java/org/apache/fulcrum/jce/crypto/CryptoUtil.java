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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8;
import org.apache.fulcrum.jce.crypto.extended.CryptoStreamFactoryJ8Template;
import org.apache.fulcrum.jce.crypto.extended.CryptoUtilJ8;

/**
 * Helper class to provde generic functions to work with CryptoStreams.
 *
 * The code uses parts from Markus Hahn's Blowfish library found at
 * http://blowfishj.sourceforge.net/
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl </a>
 * @author <a href="mailto:maakus@earthlink.net">Markus Hahn</a>
 */

public class CryptoUtil {

    /** the default instance */
    private static CryptoUtil instance;
    
    
    protected CryptoStreamFactory cryptoStreamFactory;
    
    /**
     * Factory method to get a default instance
     * 
     * @return an instance of the CryptoUtil
     */
    public synchronized static CryptoUtil getInstance() {
        if (CryptoUtil.instance == null) {
            CryptoUtil.instance = new CryptoUtil();
        }

        return CryptoUtil.instance;
    }
    
    /**
     * 
     */
    protected CryptoUtil() {
        cryptoStreamFactory = CryptoStreamFactoryImpl.getInstance();
    }
    
    /**
     * Factory method to get a default instance
     * 
     * @param salt the salt for the PBE algorithm
     * @param count the iteration for PBEParameterSpec
     * @return an instance of the CryptoUtil
     */
    public synchronized static CryptoUtil getInstance(byte[] salt, int count) {
        if (CryptoUtil.instance == null) {
            CryptoUtil.instance = new CryptoUtil(salt, count);
        }

        return CryptoUtil.instance;
    }
    
    /**
     *  @param salt the salt for the PBE algorithm
     *  @param count the iteration for PBEParameterSpec
     */
    protected CryptoUtil(byte[] salt, int count) {
        cryptoStreamFactory = CryptoStreamFactoryImpl.getInstance(salt, count);
    }

    /**
     * Copies from a source to a target object using encryption
     *
     * @param source   the source object
     * @param target   the target object
     * @param password the password to use for encryption
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException              accessing the souce failed
     *
     */
    public void encrypt(Object source, Object target, char[] password) throws GeneralSecurityException, IOException {
        encrypt(getCryptoStreamFactory(), source, target, password);
    }

    /**
     * Copies from a source to a target object using encryption and a caller
     * supplied CryptoStreamFactory.
     *
     * @param factory  the factory to create the crypto streams
     * @param source   the source object
     * @param target   the target object
     * @param password the password to use for encryption
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException              accessing the souce failed
     */
    public void encrypt(CryptoStreamFactory factory, Object source, Object target, char[] password)
            throws GeneralSecurityException, IOException {
        InputStream is = StreamUtil.createInputStream(source);
        OutputStream os = StreamUtil.createOutputStream(target);
        OutputStream eos = factory.getOutputStream(os, password);
        StreamUtil.copy(is, eos);
    }

    
    /**
     * Encrypts a string into a hex string using {@link CryptoParametersJ8#CLEAR_CODE_DEFAULT}
     *
     * @param plainText the plain text to be encrypted
     * @param password  the password for encryption
     * @return the encrypted string
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException              accessing the souce failed
     */
    public String encryptStringWithClearCode(String plainText, char[] password) throws GeneralSecurityException, IOException {
        return encryptString(getCryptoStreamFactory(), plainText, password, true);
    }

    /**
     * Encrypts a string into a hex string.
     *
     * @param plainText the plain text to be encrypted
     * @param password  the password for encryption
     * @return the encrypted string
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException              accessing the souce failed
     */
    public String encryptString(String plainText, char[] password) throws GeneralSecurityException, IOException {
        return encryptString(getCryptoStreamFactory(), plainText, password, false);
    }

    /**
     * Encrypts a string into a hex string.
     *
     * @param factory   the factory to create the crypto streams
     * @param plainText the plain text to be encrypted
     * @param password  the password for encryption
     * @param withClearCode boolean to indicate, that a string containing how it was decoded is included
     * @return the encrypted string
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException              accessing the souce failed
     */
    public String encryptString(CryptoStreamFactory factory, String plainText, char[] password, boolean withClearCode)
            throws GeneralSecurityException, IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        encrypt(factory, plainText, baos, password);
        String prefix =  (withClearCode)? (this instanceof CryptoUtilJ8)?
        		((CryptoStreamFactoryJ8Template)((CryptoUtilJ8)this).getCryptoStreamFactory()).getType().getClearCode()
            	: CryptoParametersJ8.CLEAR_CODE_DEFAULT: "";
        return prefix + HexConverter.toString(baos.toByteArray());
    }
    
    /**
     * Copies from a source to a target object using decryption.
     *
     * @param source   the source object
     * @param target   the target object
     * @param password the password to use for decryption
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException              accessing the souce failed
     */
    public void decrypt(Object source, Object target, char[] password) throws GeneralSecurityException, IOException {
        decrypt(getCryptoStreamFactory(), source, target, password);
    }
    
    /**
     * Decrypts an encrypted string into the plain text. The encrypted string must
     * be a hex string created by encryptString.
     * 
     * Decrypts encrypted text after {@link CryptoParametersJ8#CLEAR_CODE_DEFAULT}.
     * 
     * Removes ClearCode length of 10 bit, before decrpyting expected as prefix.
     *
     * @param cipherText the encrypted text to be decrypted
     * @param password   the password for decryption
     * @return the decrypted string
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException              accessing the souce failed
     */
    public String decryptStringWithClearCode(String cipherText, char[] password) throws GeneralSecurityException, IOException {
        return decryptString(getCryptoStreamFactory(), cipherText.substring(10), password);
    }

    /**
     * Decrypts an encrypted string into the plain text. The encrypted string must
     * be a hex string created by encryptString.
     *
     * @param cipherText the encrypted text to be decrypted
     * @param password   the password for decryption
     * @return the decrypted string
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException              accessing the souce failed
     */
    public String decryptString(String cipherText, char[] password) throws GeneralSecurityException, IOException {
        return decryptString(getCryptoStreamFactory(), cipherText, password);
    }
    
    /**
     * Decrypts an encrypted string into the plain text. The encrypted string must
     * be a hex string created by encryptString.
     *
     * @param cipherText the encrypted text to be decrypted
     * @param password   the password for decryption
     * @param withClearCode boolean to indicate, that a string containing how it was decoded was included during encryption
     * @return the decrypted string
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException              accessing the souce failed
     */
    public String decryptString(String cipherText, char[] password, boolean withClearCode) throws GeneralSecurityException, IOException {
        return decryptString(getCryptoStreamFactory(), withClearCode?
                cipherText.substring(CryptoParametersJ8.CLEAR_CODE_DEFAULT.length()):
                cipherText, password);
    }

    /**
     * Copies from a source to a target object using decryption and a caller-suppier
     * CryptoStreamFactory.
     *
     * @param factory  the factory to create the crypto streams
     * @param source   the source object
     * @param target   the target object
     * @param password the password to use for decryption
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException              accessing the souce failed
     */
    protected void decrypt(CryptoStreamFactory factory, Object source, Object target, char[] password)
            throws GeneralSecurityException, IOException {
        InputStream is = StreamUtil.createInputStream(source);
        OutputStream os = StreamUtil.createOutputStream(target);
        InputStream dis = factory.getInputStream(is, password);
        StreamUtil.copy(dis, os);
    }

    /**
     * Decrypts an encrypted string into the plain text. The encrypted string must
     * be a hex string created by encryptString.
     *
     * @param factory    the factory to create the crypto streams
     * @param cipherText the encrypted text to be decrypted
     * @param password   the password for decryption
     * @return the decrypted string
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException              accessing the souce failed
     */
    public String decryptString(CryptoStreamFactory factory, String cipherText, char[] password)
            throws GeneralSecurityException, IOException {
        byte[] buffer = HexConverter.toBytes(cipherText);
        ByteArrayOutputStream bais = new ByteArrayOutputStream();
        decrypt(factory, buffer, bais, password);
        return new String(bais.toByteArray(), "utf-8");
    }

    /**
     * Pumps the input stream to the output stream.
     *
     * @param is the source input stream
     * @param os the target output stream
     * @return the number of bytes copied
     * @throws IOException the copying failed
     * @deprecated use StreamUtil instead
     */
    public static long copy(InputStream is, OutputStream os) throws IOException {
        return StreamUtil.copy(is, os);
    }

    /**
     * @return the CryptoStreamFactory to be used
     */
    public CryptoStreamFactory getCryptoStreamFactory() {
        return cryptoStreamFactory;
    }
    
}
