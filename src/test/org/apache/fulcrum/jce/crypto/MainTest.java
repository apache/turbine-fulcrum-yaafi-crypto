package org.apache.fulcrum.jce.crypto;

import org.apache.fulcrum.jce.crypto.cli.CLI;

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

import junit.framework.TestCase;

/**
 * Test suite for crypto functionality
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl</a>
 */

public class MainTest extends TestCase
{
    /** the password to be used */
    private String password;

    /**
     * Constructor
     * @param name the name of the test case
     */
    public MainTest( String name )
    {
        super(name);

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
    public void testStringEncryption()
    {
        String[] encryptionArgs = { "string", "enc", this.password, "mysecretpassword"};
        CLI.main(encryptionArgs);
        String[] decryptionArgs = { "string", "dec", this.password, "9330419fc003b4e1461986782625db13f4c8c81c340a9caa"};
        CLI.main(decryptionArgs);
    }
    
    public void testAnotherStringEncryption()
    {
        String[] encryptionArgs = { "string", "enc", this.password, "secret"};
        CLI.main(encryptionArgs);
        String[] decryptionArgs = { "string", "dec", this.password, "39619852d48491af"};
        CLI.main(decryptionArgs);
    }

    /** Encrypt a text file on the command line */
    public void testFileEncryption1()
    {
        String[] encryptionArgs = { "file", "enc", this.password, "./src/test/data/plain.txt", "./target/main/plain.enc.txt" };
        String[] decryptionArgs = { "file", "dec", this.password, "./target/main/plain.enc.txt", "./target/main/plain.dec.txt" };
        CLI.main(encryptionArgs);
        CLI.main(decryptionArgs);
    }

    /** Encrypt a text file in-place on the command line */
    public void testFileEncryption2()
    {
        String[] encryptionArgs = { "file", "enc", this.password, "./src/test/data/plain.txt", "./target/main/plain.txt" };
        String[] decryptionArgs = { "file", "dec", this.password, "./target/main/plain.txt" };
        CLI.main(encryptionArgs);
        CLI.main(decryptionArgs);
    }

}