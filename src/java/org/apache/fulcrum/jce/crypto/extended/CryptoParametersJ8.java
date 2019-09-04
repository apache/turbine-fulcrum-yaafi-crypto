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


/**
 * CryptoParameters used for encryption/decryption.
 *
 * @author <a href="mailto:gk@apache.org">Georg Kallidis</a>
 */

public interface CryptoParametersJ8
{

    int COUNT_J8 = 10_000; //200_000;
    
    /**
     *  @see https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunJCEProvider
     *  
     *  Algo/mode/padding for cipher transformation: 
     *  @see https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
     *  
     *  using PBEWith<digest>And<encryption>: 
     *  
     *  <li>PBEWithHmacSHA256AndAES_256/CBC/PKCS5Padding
     *  
     *  or
     *  Cipher Algorithm Names/Cipher Algorithm Modes/Cipher Algorithm Padding
     *  
     *  <li>AES/GCM/NoPadding 
     */
    
    public enum TYPES_IMPL {
        ALGORITHM_J8_PBE("PBEWithHmacSHA256AndAES_256"), 
        ALGORITHM_J8_GCM("AES/GCM/NoPadding");
        
        private final String algorithm;
        
        private TYPES_IMPL(String algo) {
            algorithm = algo;
        }
        @Override
        public String toString() {
            return this.algorithm;
        }
        public String getAlgorithm() {
            return algorithm;
        }
    }
    
    public enum TYPES {
        PBE, GCM
    }
    
    /**
     * Prefix to decrypted hex hash to get a clue, what to use and what it is.
     * 
     * This should be always 10 bytes
     */
    String CLEAR_CODE_J8 = "J8_AES256;"; //
}
