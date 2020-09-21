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
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl </a>
 */

public interface CryptoStreamFactory
{
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
    InputStream getInputStream(InputStream is, String decryptionMode)
        throws GeneralSecurityException, IOException;

    /**
     * Creates input stream based on the decryption mode
     * using the given password.
     *
     * @param is the input stream to be wrapped
     * @param decryptionMode the decryption mode (true|false|auto)
     * @param password the password to be used
     * @return an decrypting input stream
     * @throws GeneralSecurityException creating the input stream failed
     * @throws IOException creating the input stream failed
     */
    InputStream getInputStream(InputStream is, String decryptionMode, char[] password)
        throws GeneralSecurityException, IOException;

    /**
     * Creates a decrypting input stream using the default password.
     *
     * @param is the input stream to be wrapped
     * @return an decrypting input stream
     * @throws GeneralSecurityException creating the input stream failed
     * @throws IOException creating the input stream failed
     */
    InputStream getInputStream(InputStream is)
        throws GeneralSecurityException, IOException;

    /**
     * Creates an decrypting input stream using a given password.
     *
     * @param is the input stream to be wrapped
     * @param password the password to be used
     * @return an decrypting input stream
     * @throws GeneralSecurityException creating the input stream failed
     * @throws IOException creating the input stream failed
     */
    InputStream getInputStream(InputStream is, char[] password)
        throws GeneralSecurityException, IOException;

    /**
     * Creates a smart decrypting input stream using the default
     * password. The implementation looks at the binary content
     * to decide if it was encrypted or not thereby providing
     * transparent access to encrypted/unencrypted files.
     *
     * @param is the input stream to be wrapped
     * @return an decrypting input stream
     * @throws GeneralSecurityException creating the input stream failed
     * @throws IOException creating the input stream failed
     */
    InputStream getSmartInputStream(InputStream is)
        throws GeneralSecurityException, IOException;

    /**
     * Creates a smart decrypting input stream using a given
     * password. The implementation looks at the binary content
     * to decide if it was encrypted or not thereby providing
     * transparent access to encrypted/unencrypted files.
     *
     * @param is the input stream to be wrapped
     * @param password the password to be used
     * @return an decrypting input stream
     * @throws GeneralSecurityException creating the input stream failed
     * @throws IOException creating the input stream failed
     */
    InputStream getSmartInputStream(InputStream is, char[] password)
        throws GeneralSecurityException, IOException;

    /**
     * Creates an encrypting output stream using the default password.
     *
     * @param os the output stream to be wrapped
     * @return an encrypting output stream
     * @throws GeneralSecurityException creating the output stream failed
     * @throws IOException creating the output stream failed
     */
    OutputStream getOutputStream(OutputStream os)
        throws GeneralSecurityException, IOException;

    /**
     * Creates an encrypting output stream using the given password.
     *
     * @param os the output stream to be wrapped
     * @param password the password to be used
     * @return an encrypting output stream
     * @throws GeneralSecurityException creating the output stream failed
     * @throws IOException creating the output stream failed
     */
    OutputStream getOutputStream(OutputStream os, char[] password)
        throws GeneralSecurityException, IOException;

    /**
     * Info about used algorithm.
     * @return algorithm string 
     */
    String getAlgorithm();
    
}
