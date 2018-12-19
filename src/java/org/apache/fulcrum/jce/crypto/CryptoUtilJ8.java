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

/**
 * Helper class to provde generic functions to work with CryptoStreams.
 *
 * The code uses parts from Markus Hahn's Blowfish library found at
 * http://blowfishj.sourceforge.net/
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl </a>
 * @author <a href="mailto:maakus@earthlink.net">Markus Hahn</a>
 */

public final class CryptoUtilJ8 extends CryptoUtil {

    
    /** the default instance */
    private static CryptoUtilJ8 instance;
    
    /**
     * Factory method to get a default instance
     * @return an instance of the CryptoStreamFactory
     */
    public synchronized static CryptoUtilJ8 getInstance()
    {
        if( CryptoUtilJ8.instance == null )
        {
            CryptoUtilJ8.instance = new CryptoUtilJ8();
        }

        return CryptoUtilJ8.instance;
    }

    /**
     * Encrypts a string into a hex string.
     *
     * @param factory   the factory to create the crypto streams
     * @param plainText the plain text to be encrypted
     * @param password  the password for encryption
     * @return the encrypted string
     * @throws GeneralSecurityException accessing JCE failed
     * @throws IOException              accessing the souce failed
     */
    @Override
    public String encryptString(CryptoStreamFactory factory, String plainText, char[] password)
            throws GeneralSecurityException, IOException {
        ByteArrayOutputStream bais = new ByteArrayOutputStream();
        encrypt(factory, plainText, bais, password);
        return HexConverter.toString(bais.toByteArray());
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
    @Override
    public void encrypt(CryptoStreamFactory factory, Object source, Object target, char[] password)
            throws GeneralSecurityException, IOException {
        InputStream is = StreamUtil.createInputStream(source);
        OutputStream os = StreamUtil.createOutputStream(target);
        OutputStream eos = ((CryptoStreamFactoryJ8)factory).getOutputStream(is, os, password);
        // StreamUtil.copy( is, eos );
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
    @Override
    public void decrypt(CryptoStreamFactory factory, Object source, Object target, char[] password)
            throws GeneralSecurityException, IOException {
        InputStream is = StreamUtil.createInputStream(source);
        OutputStream os = StreamUtil.createOutputStream(target);
        InputStream dis = factory.getInputStream(is, password);
        StreamUtil.copy(dis, os);
    }

    /**
     * @return the CryptoStreamFactory to be used
     */
    public CryptoStreamFactory getCryptoStreamFactory() {
        return CryptoStreamFactoryJ8Impl.getInstance();
    }
}
