package org.apache.fulcrum.jce.crypto.extended;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.apache.fulcrum.jce.crypto.PasswordFactory;
import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8.TYPES;
import org.apache.fulcrum.jce.junit5.extension.SupportedTypeArguments;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
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
public class CryptoUtilJ8ExplicitParamsTest {
    /** the password to be used */
    private String password;

    /** the test data directory */
    private File testDataDirectory;

    /** the temp data director */
    private File tempDataDirectory;
    
	
	private static byte[] SALT = generateSalt();
	
	private static int COUNT = 12345;
    
    private static List<CryptoUtilJ8> cryptoUtilJ8s = new ArrayList<>();

    private static Logger log = LogManager.getLogger(CryptoUtilJ8ExplicitParamsTest.class);
    
    
    protected static byte[] generateSalt() {
        SecureRandom random;
        try {
            random = SecureRandom.getInstanceStrong();
            byte[] salt = new byte[ 16 ];
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
    public CryptoUtilJ8ExplicitParamsTest() {

        this.password = "mysecret";
        this.testDataDirectory = new File("./src/test/data");
        this.tempDataDirectory = new File("./target/temp");
        this.tempDataDirectory.mkdirs();
    }


    @BeforeAll
    public static void setUp() throws Exception {
        cryptoUtilJ8s.clear();
        SupportedTypeArguments.init();
        for (TYPES type : CryptoParametersJ8.TYPES.values()) {
            if (SupportedTypeArguments.SUPPORTED_TYPES.contains(type.toString())) {
            	cryptoUtilJ8s.add(CryptoUtilJ8.getInstance(type, SALT, COUNT));
            }
        }
        for (CryptoUtilJ8 cryptoUtilJ8 : cryptoUtilJ8s) {
            log.debug("registered {}", cryptoUtilJ8.getClass().getSimpleName() );
            CryptoStreamFactoryJ8Template crt = ((CryptoStreamFactoryJ8Template)cryptoUtilJ8.getCryptoStreamFactory());
            log.debug(String.format("created default crypto factory instance %s for algo %s with salt length: %s", 
               		crt.getClass().getSimpleName(),
               		crt.getAlgorithm(), crt.getSalt().length));
        }
    }
    
    @AfterAll
    public static void destroy() {
        cryptoUtilJ8s.clear();
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
     * 
     */
    @Test
    public void testTextEncryption()  {
        
        File sourceFile = new File(this.getTestDataDirectory(), "plain.txt");
        File targetFile = new File(this.getTempDataDirectory(), "plain.j8.enc.txt");
        
        cryptoUtilJ8s.forEach(cuj8 -> {
            try {
                cuj8.encrypt(sourceFile, targetFile, this.getPassword());
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
                fail();
            } catch (IOException e) {
                e.printStackTrace();
                fail();
            }
        } );
    }

    /** Decrypt a text file 
     */
    @Test
    public void testTextDecryption() {           
    	cryptoUtilJ8s.forEach(cuj8 -> { 
            log.info("start en-/decrypting with {}",cuj8);    
    		try {
                    File sourceFile = new File(this.getTestDataDirectory(), "plain.txt");
                    File targetFile = new File(this.getTempDataDirectory(), "plain.j8.enc.txt");
                    cuj8.encrypt(sourceFile, targetFile, this.getPassword());
                    
                    File sourceFile2 = new File(this.getTempDataDirectory(), "plain.j8.enc.txt");;
                    File targetFile2 = new File(this.getTempDataDirectory(), "plain.j8.dec.txt");
                    cuj8.decrypt(sourceFile2, targetFile2.getAbsolutePath(), this.getPassword());
                    assertEquals(
                            new String(Files.readAllBytes( Paths.get(sourceFile.toURI())) ), 
                            new String(Files.readAllBytes( Paths.get(targetFile2.toURI())) )
                            );
                } catch (GeneralSecurityException | IOException e) {
                    e.printStackTrace();
                    fail();
                }
            });
    }
    
    /** Encrypt a PDF file 
     * 
     */
    @Test
    public void testPdfEncryption() {
        File sourceFile = new File(this.getTestDataDirectory(), "plain.pdf");
        File targetFile = new File(this.getTempDataDirectory(), "plain.j8.enc.pdf");
        cryptoUtilJ8s.forEach(cuj8 -> { 
            try {
                cuj8.encrypt(sourceFile, targetFile, this.getPassword());
            } catch (GeneralSecurityException | IOException e) {
                e.printStackTrace();
                fail();
            }    
        });        
    }

    /** Decrypt a PDF file 
     * 
     */
    @Test
    public void testPdfDecryption()  {
        //testPdfEncryption();
        cryptoUtilJ8s.forEach(cuj8 -> { 
            try {
                File sourceFile = new File(this.getTestDataDirectory(), "plain.pdf");
                File targetFile = new File(this.getTempDataDirectory(), "plain.j8.enc.pdf");
                cuj8.encrypt(sourceFile, targetFile, this.getPassword());
                
                File sourceFile2 = new File(this.getTempDataDirectory(), "plain.j8.enc.pdf");
                File targetFile2 = new File(this.getTempDataDirectory(), "plain.j8.dec.pdf");
                cuj8.decrypt(sourceFile2, targetFile2, this.getPassword());
                
                assertEquals(
                        new String(Files.readAllBytes( Paths.get(sourceFile.toURI())) ), 
                        new String(Files.readAllBytes( Paths.get(targetFile2.toURI())) )
                        );
            } catch (GeneralSecurityException | IOException e) {
                e.printStackTrace();
                fail();
            }    
        }); 

    }

    /** Test encryption and decryption of Strings
     * 
     */
    @Test
    public void testStringEncryption() {
        char[] testVector = new char[513];

        for (int i = 0; i < testVector.length; i++) {
            testVector[i] = (char) i;
        }

        String source = new String(testVector);
        cryptoUtilJ8s.forEach(cuj8 -> { 
            String cipherText;
            String plainText;
            try {
                cipherText = cuj8.encryptString(source, this.getPassword());
                plainText = cuj8.decryptString(cipherText, this.getPassword());
                assertEquals(source, plainText, source +" is not equal with " + plainText); 
            } catch (GeneralSecurityException | IOException e) {
                e.printStackTrace();
                fail();
            }
           
        });
        

    }

    /** Test encryption and decryption of Strings
     */
    @Test
    public void testStringHandling()  {
        String source = "Nobody knows the toubles I have seen ...";
        cryptoUtilJ8s.forEach(cuj8 -> { 
            String cipherText;
            try {
                cipherText = cuj8.encryptString(source, this.getPassword());
                String plainText = cuj8.decryptString(cipherText, this.getPassword());
                assertEquals(source, plainText);   
            } catch (GeneralSecurityException | IOException e) {
                e.printStackTrace();
                fail();
            }
         
        });

    }

    /** 
     * Test creating a password
     * @throws Exception Generic exception
     */
    @Test
    public void testPasswordFactory() throws Exception {
        char[] result = null;
        result = PasswordFactory.getInstance("SHA-256").create();
        log.debug("random pw: {}", new String(result));
        result = PasswordFactory.getInstance("SHA-256",10_000).create(this.getPassword());
        log.debug("password pw with seed: {}", new String(result));
        assertNotNull(result);
        return;
    }
    
    /** Test encryption and decryption of binary data
     * @throws Exception Generic exception
     */
    @Test
    public void testBinaryHandling() throws Exception {
        
        cryptoUtilJ8s.forEach(cuj8 -> { 
            byte[] source = new byte[256];
            byte[] result = null;

            for (int i = 0; i < source.length; i++) {
                source[i] = (byte) i;
            }

            ByteArrayOutputStream cipherText = new ByteArrayOutputStream();
            ByteArrayOutputStream plainText = new ByteArrayOutputStream();
            try {
                cuj8.encrypt(source, cipherText, this.getPassword());
                cuj8.decrypt(cipherText, plainText, this.getPassword());
            } catch (GeneralSecurityException | IOException e) {
                e.printStackTrace();
                fail();
            }
            result = plainText.toByteArray();

            for (int i = 0; i < source.length; i++) {
                if (source[i] != result[i]) {
                    fail("Binary data are different at position " + i);
                }
            }
        });

       

    }
    
    /** 
     * Test encryption and decryption of Strings 
     */
    @Test
    public void testStringWithPasswordEncryption() {
        char[] password = "57cb-4a23-d838-45222".toCharArray();
        String source = "e02c-3b76-ff1e-5d9a1";
        
        cryptoUtilJ8s.forEach(cuj8 -> { 
            String cipherText = null;
            try {
                cipherText = cuj8.encryptString(source, password);
                log.debug(cipherText);// about 128
                
                log.debug("registered {}: {}", cuj8.getClass().getSimpleName());
                CryptoStreamFactoryJ8Template crt = ((CryptoStreamFactoryJ8Template)cuj8.getCryptoStreamFactory());
                log.debug(String.format("created default crypto factory instance %s for algo %s with salt (optional): %s", 
               		crt.getClass().getSimpleName(),
               		crt.getAlgorithm(), crt.getSalt()));
                
                log.debug("length for {} is: {}", crt.getType(), cipherText.length());// about 128
                if (crt.getType() == TYPES.PBE) {
                    assertEquals(128, cipherText.length()); // 128bytes + 10 bytes for cleartext
                } 
                CryptoStreamFactoryJ8Template.resetInstances();
                String plainText = cuj8.decryptString(cipherText, password);
                assertEquals(source, plainText);
            } catch (GeneralSecurityException | IOException e) {
                e.printStackTrace();
                fail();
            }
            
        });      

    }

}
