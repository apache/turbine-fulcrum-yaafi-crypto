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


/**
 * CryptoParameters used for encryption/decrytpion.
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl</a>
 */

public interface CryptoParameters
{
    /** Parameter for PBEParameterSpec */
    int COUNT = 20;
    
    int COUNT_J8 = 10_000; //200_000;

    /** The password salt */
    byte[] SALT = {
        (byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c,
        (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
        };

    /** The crypto algorithm being used */
    String ALGORITHM = "PBEWithMD5AndDES";
    
    /**
     *  @see https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunJCEProvider
     *  
     *  Algo/mode/padding for cipher transformation: 
     *  @see https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
     *  
     *  PBEWithHmacSHA256AndAES_256/CBC/PKCS5Padding, PBEWithHmacSHA256AndAES_128/CBC/PKCS5Padding
     */
    String ALGORITHM_J8 = "PBEWithHmacSHA256AndAES_256"; //"PBEWithHmacSHA256AndAES_128 ";
    
    /**
     * Prefix to decrypted hex hash to get a clue, what to use and what it is.
     * 
     * This should be always 10 bytes
     */
    String CLEAR_CODE_J8 = "J8_AES256;"; //
}
