package org.apache.fulcrum.jce.crypto.extended;

import org.apache.fulcrum.jce.crypto.cli.CLI2;
import org.junit.jupiter.api.Test;

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
 * Test suite for crypto functionality
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl</a>
 */

public class Main8Test
{
    /** the password to be used */
    static private String password;
    
    /**
     * Constructor
     */
    public Main8Test() {

        this.password = "foobar";
    }
   

    /**
     * @return Returns the password.
     */
    protected char[] getPassword()
    {
        return password.toCharArray();
    }
    
    
    /** Encrypt a string on the command line */
    @Test
    public void testStringEncryption()
    {
        String[] encryptionArgs = { "string", "enc", this.password, "mysecretpassword"};
        CLI2.main(encryptionArgs);
        String[] decryptionArgs = { "string", "dec", this.password, "ce3bf02da8a57c94b4f42c084230d1bedcd856c49a3fd23ec59835ca46a3d37ee02d470394691353478c905e7b342316d1fcc3e1b98837bf0595ef50853922df"};
        CLI2.main(decryptionArgs);
    }
    @Test
    public void testAnotherStringEncryption()
    {
        String[] encryptionArgs = { "string", "enc", this.password, "secret"};
        CLI2.main(encryptionArgs);
        String[] decryptionArgs = { "string", "dec", this.password, "8626904c9e64fddfa64add56472c4796429b0adb7c8039424adef7434be6bc255ce092011e8c560965814e806dd68117"};
        CLI2.main(decryptionArgs);
    }
    @Test
    /** Encrypt a text file on the command line */
    public void testFileEncryption1()
    {
        String[] encryptionArgs = { "file", "enc", this.password, "./src/test/data/plain.txt", "./target/main8/plain.enc.txt" };
        String[] decryptionArgs = { "file", "dec", this.password, "./target/main8/plain.enc.txt", "./target/main8/plain.dec.txt" };
        CLI2.main(encryptionArgs);
        CLI2.main(decryptionArgs);
    }
    @Test
    /** Encrypt a text file in-place on the command line */
    public void testFileEncryption2()
    {
        String[] encryptionArgs = { "file", "enc", this.password, "./src/test/data/plain.txt", "./target/main8/plain.txt" };
        String[] decryptionArgs = { "file", "dec", this.password, "./target/main8/plain.txt" };
        CLI2.main(encryptionArgs);
        CLI2.main(decryptionArgs);
    }

}