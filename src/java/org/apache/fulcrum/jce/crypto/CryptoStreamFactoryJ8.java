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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 * Interface for creating encrypting/decrypting streams. 
 *
 * @author <a href="mailto:gk@apache.org">Georg Kallidis </a>
 */

public interface CryptoStreamFactoryJ8 extends CryptoStreamFactory
{
    /**
     * Creates an encrypting output stream using the given password.
     *
     * @param is the input stream to be encoded
     * @param os the output stream to be wrapped
     * @param password the password to be used
     * @return the encrypting output stream
     * @throws GeneralSecurityException creating the output stream failed
     * @throws IOException creating the output stream failed
     */
    OutputStream getOutputStream(InputStream is, OutputStream os, char[] password)
        throws GeneralSecurityException, IOException;
    
    /**
     * Creates input stream based on the decryption mode
     * using the default password.
     *
     * @param is the input stream to be wrapped
     * @param decryptionMode the decryption mode (true|false|auto)
     * @return an decrypting input stream
     * @throws GeneralSecurityException creating the input stream failed
     * @throws IOException creating the input stream failed
     */
    InputStream getInputStream(InputStream is, char[] password)
            throws GeneralSecurityException, IOException;
}
