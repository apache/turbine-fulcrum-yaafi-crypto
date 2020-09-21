package org.apache.fulcrum.jce.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

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
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Test suite for crypto functionality
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl</a>
 */

public class CryptoUtilExplicitParamsTest {
	/** the password to be used */
	private String password;

	/** the test data directory */
	private File testDataDirectory;

	/** the temp data director */
	private File tempDataDirectory;
	
	private static Logger log = LogManager.getLogger(CryptoUtilExplicitParamsTest.class);
	
	private static byte[] SALT = Salt();
	
	private static int COUNT = 25;
	
	 public static byte[] Salt()
	 {
		SecureRandom random;
		try {
			random = SecureRandom.getInstanceStrong();
	        byte[] salt = new byte[ 8 ];
	        random.nextBytes(salt);
	        return salt;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	 }

	/**
	 * Constructor
	 */
	public CryptoUtilExplicitParamsTest() {
		this.password = "mysecret";
		this.testDataDirectory = new File("./src/test/data");
		this.tempDataDirectory = new File("./target/temp");
		this.tempDataDirectory.mkdirs();
	}

	/**
	 * 
	 * @throws Exception Generic exception
	 */
	@BeforeAll
	protected static void setUp() throws Exception {
	}

	/**
	 * @return Returns the password.
	 */
	protected char[] getPassword() {
		return password.toCharArray();
	}

	/**
	 * @return Returns the tempDataDirectory.
	 */
	protected File getTempDataDirectory() {
		return tempDataDirectory;
	}

	/**
	 * @return Returns the testDataDirectory.
	 */
	protected File getTestDataDirectory() {
		return testDataDirectory;
	}

	/** Encrypt a text file 
	 */
	@Test
	public void testTextEncryption()  {
		File sourceFile = new File(this.getTestDataDirectory(), "plain.txt");
		File targetFile = new File(this.getTempDataDirectory(), "plain.enc.txt");
		try {
			CryptoUtil.getInstance(SALT,COUNT).encrypt(sourceFile, targetFile, this.getPassword());
		} catch (GeneralSecurityException e) {
			fail(e);
		} catch (IOException e) {
			fail(e);
		}
	}

	/** Decrypt a text file 
	 */
	@Test
	public void testTextDecryption()  {
		testTextEncryption();
		File sourceFile = new File(this.getTempDataDirectory(), "plain.enc.txt");
		File targetFile = new File(this.getTempDataDirectory(), "plain.dec.txt");
		try {
			CryptoUtil.getInstance(SALT,COUNT).decrypt(sourceFile, targetFile.getAbsolutePath(), this.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
	}

	/** Encrypt an empty text file 
	 */
	@Test
	public void testEmptyTextEncryption() {
		File sourceFile = new File(this.getTestDataDirectory(), "empty.txt");
		File targetFile = new File(this.getTempDataDirectory(), "empty.enc.txt");
		try {
			CryptoUtil.getInstance(SALT,COUNT).encrypt(sourceFile, targetFile, this.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
	}

	/** Decrypt a text file
	 */
	@Test
	public void testEmptyTextDecryption() {
		testEmptyTextEncryption();
		File sourceFile = new File(this.getTempDataDirectory(), "empty.enc.txt");
		File targetFile = new File(this.getTempDataDirectory(), "empty.dec.txt");
		try {
			CryptoUtil.getInstance(SALT,COUNT).decrypt(sourceFile, targetFile, this.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
	}

	/** Encrypt a PDF file 
	 */
	@Test
	public void testPdfEncryption()  {
		File sourceFile = new File(this.getTestDataDirectory(), "plain.pdf");
		File targetFile = new File(this.getTempDataDirectory(), "plain.enc.pdf");
		try {
			CryptoUtil.getInstance(SALT,COUNT).encrypt(sourceFile, targetFile, this.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
	}

	/** Decrypt a PDF file 
	 */
	@Test
	public void testPdfDecryption() {
		testPdfEncryption();
		File sourceFile = new File(this.getTempDataDirectory(), "plain.enc.pdf");
		File targetFile = new File(this.getTempDataDirectory(), "plain.dec.pdf");
		try {
			CryptoUtil.getInstance(SALT,COUNT).decrypt(sourceFile, targetFile, this.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
	}

	/** Encrypt a ZIP file 
	 */
	@Test
	public void testZipEncryption()  {
		File sourceFile = new File(this.getTestDataDirectory(), "plain.zip");
		File targetFile = new File(this.getTempDataDirectory(), "plain.enc.zip");
		try {
			CryptoUtil.getInstance(SALT,COUNT).encrypt(sourceFile, targetFile, this.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
	}

	/** Decrypt a ZIP file 
	 */
	@Test
	public void testZipDecryption()  {
		testZipEncryption();
		File sourceFile = new File(this.getTempDataDirectory(), "plain.enc.zip");
		File targetFile = new File(this.getTempDataDirectory(), "plain.dec.zip");
		try {
			CryptoUtil.getInstance(SALT,COUNT).decrypt(sourceFile, targetFile, this.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
	}

	/** Encrypt a UTF-16 XML file 
	 */
	@Test
	public void testXmlUTF16Encryption()  {
		File sourceFile = new File(this.getTestDataDirectory(), "plain-utf16.xml");
		File targetFile = new File(this.getTempDataDirectory(), "plain-utf16.enc.xml");
		try {
			CryptoUtil.getInstance(SALT,COUNT).encrypt(sourceFile, targetFile, this.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
	}

	/**
	 * Decrypt a UTF-16 XML file
	 */
	 @Test
	public void testXMLUTF16Decryption() {
		testXmlUTF16Encryption();
		File sourceFile = new File(this.getTempDataDirectory(), "plain-utf16.enc.xml");
		File targetFile = new File(this.getTempDataDirectory(), "plain-utf16.dec.xml");
		try {
			CryptoUtil.getInstance(SALT,COUNT).decrypt(sourceFile, targetFile, this.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
	}

	/**
	 * Encrypt a UTF-8 XML file
	 */
	 @Test
	public void testXmlUTF8Encryption() {
		File sourceFile = new File(this.getTestDataDirectory(), "plain-utf8.xml");
		File targetFile = new File(this.getTempDataDirectory(), "plain-utf8.enc.xml");
		try {
			CryptoUtil.getInstance(SALT,COUNT).encrypt(sourceFile, targetFile, this.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
	}

	/**
	 * Decrypt a UTF-8 XML file
	 */
	 @Test
	public void testXMLUTF8Decryption() {
		testXmlUTF8Encryption();
		File sourceFile = new File(this.getTempDataDirectory(), "plain-utf8.enc.xml");
		File targetFile = new File(this.getTempDataDirectory(), "plain-utf8.dec.xml");
		try {
			CryptoUtil.getInstance(SALT,COUNT).decrypt(sourceFile, targetFile, this.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
	}

	/**
	 * Encrypt a ISO-8859-1 XML file
	 */
	@Test
	public void testXmlISO88591Encryption()  {
		File sourceFile = new File(this.getTestDataDirectory(), "plain-iso-8859-1.xml");
		File targetFile = new File(this.getTempDataDirectory(), "plain-iso-8859-1.enc.xml");
		try {
			CryptoUtil.getInstance(SALT,COUNT).encrypt(sourceFile, targetFile, this.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
	}

	/**
	 * Decrypt a ISO-8859-1 XML file
	 */
	@Test
	public void testXmlISO88591Decryption()  {
		testXmlISO88591Encryption();
		File sourceFile = new File(this.getTempDataDirectory(), "plain-iso-8859-1.enc.xml");
		File targetFile = new File(this.getTempDataDirectory(), "plain-iso-8859-1.dec.xml");
		try {
			CryptoUtil.getInstance(SALT,COUNT).decrypt(sourceFile, targetFile, this.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
	}

	/** Test encryption and decryption of Strings
	 */
	@Test
	public void testStringEncryption()  {
		char[] testVector = new char[513];

		for (int i = 0; i < testVector.length; i++) {
			testVector[i] = (char) i;
		}

		String source = new String(testVector);
		try {
			String cipherText = CryptoUtil.getInstance(SALT,COUNT).encryptString(source, this.getPassword());
			String plainText = CryptoUtil.getInstance(SALT,COUNT).decryptString(cipherText, this.getPassword());
			assertEquals(source, plainText);
		} catch (GeneralSecurityException | IOException e) {
			fail(e);
		}
		
	}
	
	@Test
	public void testStringEncryptionWithType() {
		CryptoUtil cu = CryptoUtil.getInstance(SALT,COUNT);
		char[] testVector = new char[513];

		for (int i = 0; i < testVector.length; i++) {
			testVector[i] = (char) i;
		}

		String source = new String(testVector);
		String cipherText = null;
		String plainText = null;
		try {
			log.info("Test without clearTextHeader");
			cipherText = cu.encryptString(source, this.getPassword());
			log.trace(cipherText);
			plainText = cu.decryptString(cipherText, this.getPassword());
			assertEquals(source, plainText, source + " is not equal with " + plainText);

			log.info(String.format("Test with clearTextHeader %s in encrypted string.",
					CryptoParametersJ8.CLEAR_CODE_DEFAULT));
			String cipherText2 = cu.encryptStringWithClearCode(source, this.getPassword());
			log.trace(cipherText2);
			// old style
			assertTrue(cipherText2.startsWith(CryptoParametersJ8.CLEAR_CODE_DEFAULT),
					String.format("%s does not start with '%s'", cipherText2, CryptoParametersJ8.CLEAR_CODE_DEFAULT));
			String plainText2 = cu.decryptStringWithClearCode(cipherText2, this.getPassword());
			assertEquals(source, plainText2, String.format("%s is not equal with %s", source, plainText));

		} catch (GeneralSecurityException | IOException e) {
			e.printStackTrace();
			fail();
		}
	}

	/** Test encryption and decryption of Strings
	 */
	@Test
	public void testStringHandling() {
		String source = "Nobody knows the toubles I have seen ...";
		try {
			String cipherText = CryptoUtil.getInstance(SALT,COUNT).encryptString(source, this.getPassword());
			String plainText = CryptoUtil.getInstance(SALT,COUNT).decryptString(cipherText, this.getPassword());
		assertEquals(source, plainText);
		} catch (GeneralSecurityException | IOException e) {
			e.printStackTrace();
			fail();
		}
	}

	/** Test encryption and decryption of binary data
	 * @throws Exception Generic exception
	 */
	 @Test
	public void testBinaryHandling() throws Exception {
		byte[] source = new byte[256];
		byte[] result = null;

		for (int i = 0; i < source.length; i++) {
			source[i] = (byte) i;
		}

		ByteArrayOutputStream cipherText = new ByteArrayOutputStream();
		ByteArrayOutputStream plainText = new ByteArrayOutputStream();

		CryptoUtil.getInstance(SALT,COUNT).encrypt(source, cipherText, this.getPassword());
		CryptoUtil.getInstance(SALT,COUNT).decrypt(cipherText, plainText, this.getPassword());

		result = plainText.toByteArray();

		for (int i = 0; i < source.length; i++) {
			if (source[i] != result[i]) {
				fail("Binary data are different at position " + i);
			}
		}
	}

	/** Test creating a password
	 * @throws Exception Generic exception
	 */
	@Test
	public void testPasswordFactory() throws Exception {
		char[] result = null;
		result = PasswordFactory.getInstance().create();
		System.out.println(new String(result));
		result = PasswordFactory.getInstance().create(this.getPassword());
		log.info(new String(result));
		assertNotNull(result);
	}

	/** Test the hex converter
	 * @throws Exception Generic exception
	 */
	 @Test
	public void testHexConverter() throws Exception {
		String source = "DceuATAABWSaVTSIK";
		String hexString = HexConverter.toString(source.getBytes());
		String result = new String(HexConverter.toBytes(hexString));
		assertEquals(source, result);
	}

	/** Test encryption and decryption of Strings 
	 * @throws Exception Generic exception
	 */
	 @Test
	public void testPasswordEncryption() throws Exception {
		char[] password = "57cb-4a23-d838-45222".toCharArray();
		String source = "e02c-3b76-ff1e-5d9a1";
		String cipherText = CryptoUtil.getInstance(SALT,COUNT).encryptString(source, password);
		log.info(cipherText);// len 48
		assertEquals(48, cipherText.length());
		String plainText = CryptoUtil.getInstance(SALT,COUNT).decryptString(cipherText, password);
		assertEquals(source, plainText);
	}

}
