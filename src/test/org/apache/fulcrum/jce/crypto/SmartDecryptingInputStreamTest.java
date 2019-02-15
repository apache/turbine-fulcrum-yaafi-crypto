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


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;

import junit.framework.TestCase;

/**
 * Test suite for SmartDecryptingInputStream
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl</a>
 */

public class SmartDecryptingInputStreamTest extends TestCase
{
    /** the password to be used */
    private String password;

    /** the test data directory */
    private File testDataDirectory;

    /** the temp data director */
    private File tempDataDirectory;

    /**
     * Constructor
     * @param name the name of the test case
     */
    public SmartDecryptingInputStreamTest( String name )
    {
        super(name);

        this.password = "mysecret";
        this.testDataDirectory = new File( "./src/test/data" );
        this.tempDataDirectory = new File( "./temp" );
    }

    /**
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception
    {
        CryptoStreamFactoryImpl factory = new CryptoStreamFactoryImpl(
            CryptoParameters.SALT,
            CryptoParameters.COUNT
            );

        CryptoStreamFactoryImpl.setInstance( factory );
    }

    /**
     * @return Returns the password.
     */
    protected char[] getPassword()
    {
        return password.toCharArray();
    }

    /**
     * @return Returns the tempDataDirectory.
     */
    protected File getTempDataDirectory()
    {
        return tempDataDirectory;
    }

    /**
     * @return Returns the testDataDirectory.
     */
    protected File getTestDataDirectory()
    {
        return testDataDirectory;
    }

    public void testSmartEmtpyDecryption() throws Exception
    {
        this.testSmartDecryption("empty.txt","ISO-8859-1");
    }

    public void testSmartTextDecryption() throws Exception
    {
        this.testSmartDecryption("plain.txt","ISO-8859-1");
    }

    public void testSmartGroovyDecryption() throws Exception
    {
        this.testSmartDecryption("plain.groovy","ISO-8859-1");
    }

    public void testSmartXmlIso8859Utf8Decryption() throws Exception
    {
        this.testSmartDecryption("plain-iso-8859-1.xml","ISO-8859-1");
    }

    public void testSmartXmlUtf8Decryption() throws Exception
    {
        this.testSmartDecryption("plain-utf8.xml","UTF-8");
    }

    public void testSmartXmlUtf16Decryption() throws Exception
    {
        this.testSmartDecryption("plain-utf16.xml","UTF-16");
    }

    public void testPDFDecryption() throws Exception
    {
        this.testSmartDecryption("plain.pdf","ISO-8859-1");
    }

    public void testZIPDecryption() throws Exception
    {
        this.testSmartDecryption("plain.zip","ISO-8859-1");
    }

    /** Test smart decryption for a given file */
    private void testSmartDecryption( String fileName, String enc ) throws Exception
    {
        File sourceFile = new File( this.getTestDataDirectory(), fileName );
        String plainText = this.loadTextFile(sourceFile,enc);
        String smartText = this.smartDecrypt(sourceFile,enc);
        byte[] cipherText = this.encryptTextFile(sourceFile);
        String decryptedText = this.smartDecrypt(cipherText,enc);

        assertTrue( plainText.length() == smartText.length() );
        assertTrue( plainText.length() == decryptedText.length() );
        assertEquals( plainText, smartText );
        assertEquals( plainText, decryptedText );
    }

    /**
     * Loads a plain text file.
     * @param file the file to load
     */
    private String loadTextFile( File file, String enc ) throws Exception
    {
        String result = null;
        FileInputStream fis = new FileInputStream( file );
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CryptoUtil.copy(fis,baos);
        fis.close();
        result = new String( baos.toByteArray(), enc );
        return result;
    }

    /**
     * Encrypt a plain text file.
     * @param file the file to encrypt
     */
    private byte[] encryptTextFile( File file ) throws Exception
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        FileInputStream fis = new FileInputStream( file );

        CryptoUtil.getInstance().encrypt(
                CryptoStreamFactoryImpl.getInstance(),
            fis,
            baos,
            this.getPassword()
            );

        fis.close();

        return baos.toByteArray();
    }

    /**
     * Use smart decryption on a cipherText.
     *
     * @param cipherText the encrypted text
     * @return the decrypeted content
     */
    private String smartDecrypt( byte[] cipherText, String enc ) throws Exception
    {
        ByteArrayInputStream bais = new ByteArrayInputStream(cipherText);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        SmartDecryptingInputStream sdis = new SmartDecryptingInputStream(
                CryptoStreamFactoryImpl.getInstance(),
            bais,
            this.getPassword()
            );

        CryptoUtil.copy(sdis,baos);

        return new String( baos.toByteArray(), enc );
    }

    /**
     * Use smart decryption on a plain text file.
     *
     * @param file the file to load
     * @return the content
     */
    private String smartDecrypt( File file, String enc ) throws Exception
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        FileInputStream fis = new FileInputStream( file );

        SmartDecryptingInputStream sdis = new SmartDecryptingInputStream(
                CryptoStreamFactoryImpl.getInstance(),
            fis,
            this.getPassword()
            );

        CryptoUtil.copy(sdis,baos);
        return new String( baos.toByteArray(), enc );
    }

}
