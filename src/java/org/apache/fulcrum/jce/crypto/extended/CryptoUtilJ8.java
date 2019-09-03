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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.fulcrum.jce.crypto.CryptoStreamFactory;
import org.apache.fulcrum.jce.crypto.CryptoUtil;
import org.apache.fulcrum.jce.crypto.StreamUtil;
import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8.TYPES;

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

    
    public TYPES type;// default see instance
   
    
    public TYPES getType() {
        return type;
    }

    /** the typed default instances */    
    private static Map<TYPES,CryptoUtilJ8> cryptoUtilJ8s = new ConcurrentHashMap();
    
    
    /**
     * Factory method to get a default instance
     * @param type 
     * @return an instance of the CryptoStreamFactory
     */
    public static CryptoUtilJ8 getInstance(TYPES type)
    {
        synchronized (CryptoUtilJ8.class) {
            if( !cryptoUtilJ8s.containsKey(type) )
            {
                cryptoUtilJ8s.put(type, new CryptoUtilJ8(type) );
            }
    
            return cryptoUtilJ8s.get(type);
        }
    }
    
    /**
     * Factory method to get a default instance
     * 
     * default type PDC
     * @return an instance of the CryptoStreamFactory
     */
    public static CryptoUtilJ8 getInstance()
    {
        synchronized (CryptoUtilJ8.class) {
            if( cryptoUtilJ8s.isEmpty() && !cryptoUtilJ8s.containsKey(TYPES.PBE) )
            {
                cryptoUtilJ8s.put(TYPES.PBE, new CryptoUtilJ8(TYPES.PBE) );
            }
    
            return cryptoUtilJ8s.get(TYPES.PBE);
        }
    }
    
    public CryptoUtilJ8(TYPES type) {
        this.type = type;
    }
    
    public CryptoUtilJ8() {
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
     * @throws IOException              accessing the source failed
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
     * @throws IOException              accessing the source failed
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
     * 
     * @return the CryptoStreamFactory to be used
     */
    public CryptoStreamFactory getCryptoStreamFactory() {
            return CryptoStreamFactoryJ8Template.getInstance(type);
    }
}
