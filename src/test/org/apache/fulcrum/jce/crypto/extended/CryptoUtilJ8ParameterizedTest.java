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
import java.util.ArrayList;
import java.util.List;

import org.apache.fulcrum.jce.crypto.PasswordFactory;
import org.apache.fulcrum.jce.crypto.extended.CryptoStreamFactoryJ8Template;
import org.apache.fulcrum.jce.crypto.extended.CryptoUtilJ8;
import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8.TYPES;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;


/**
 * Test suite for crypto functionality
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl</a>
 */
public class CryptoUtilJ8ParameterizedTest {
    /** the password to be used */
    private String password;

    /** the test data directory */
    private File testDataDirectory;

    /** the temp data director */
    private File tempDataDirectory;
    
    private List<CryptoUtilJ8> cryptoUtilJ8s = new ArrayList<>();
    

    /**
     * Constructor
     */
    public CryptoUtilJ8ParameterizedTest() {

        this.password = "mysecret";
        this.testDataDirectory = new File("./src/test/data");
        this.tempDataDirectory = new File("./target/temp");
        this.tempDataDirectory.mkdirs();
    }

    
//    @ParameterizedTest
//    @EnumSource( TYPES.class )
//    public void setUp(TYPES type) throws Exception {
//        cryptoUtilJ8 = CryptoUtilJ8.getInstance(type); // (TYPES.PBE);
//    }

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
    
    @AfterEach
    public void setup() {
        cryptoUtilJ8s.clear(); 
    }
    
    /** Encrypt a text file 
     * @throws Exception Generic exception
     */
    @ParameterizedTest
    @EnumSource( TYPES.class )
    public void testTextEncryption(TYPES type)  {
        
        cryptoUtilJ8s.add(CryptoUtilJ8.getInstance(type));
        File sourceFile = new File(this.getTestDataDirectory(), "plain.txt");
        File targetFile = new File(this.getTempDataDirectory(), "plain.j8.enc.txt");
        
        cryptoUtilJ8s.forEach(cuj8 -> {
            try {
                System.out.println("checking "+ cuj8.getType());
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
     * @throws Exception Generic exception
     */
    @ParameterizedTest
    @EnumSource( TYPES.class )
    public void testTextDecryption(TYPES type) {
        cryptoUtilJ8s.add(CryptoUtilJ8.getInstance(type));
            cryptoUtilJ8s.forEach(cuj8 -> {
                System.out.println("checking "+ cuj8.getType());
                try {
                    File sourceFile = new File(this.getTestDataDirectory(), "plain.txt");
                    File targetFile = new File(this.getTempDataDirectory(), "plain.j8.enc.txt");
                    cuj8.encrypt(sourceFile, targetFile, this.getPassword());
                    
                    File sourceFile2 = targetFile;
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
     * @throws Exception Generic exception
     */
    @ParameterizedTest
    @EnumSource( TYPES.class )
    public void testPdfEncryption(TYPES type) {
        cryptoUtilJ8s.add(CryptoUtilJ8.getInstance(type));
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
     * @throws Exception Generic exception
     */
    @ParameterizedTest
    @EnumSource( TYPES.class )
    public void testPdfDecryption(TYPES type)  {
        cryptoUtilJ8s.add(CryptoUtilJ8.getInstance(type));
        //testPdfEncryption();
        cryptoUtilJ8s.forEach(cuj8 -> { 
            try {
                File sourceFile = new File(this.getTestDataDirectory(), "plain.pdf");
                File targetFile = new File(this.getTempDataDirectory(), "plain.j8.enc.pdf");
                cuj8.encrypt(sourceFile, targetFile, this.getPassword());
                
                File sourceFile2 = targetFile;
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
     *  @throws Exception Generic exception
     */
    @ParameterizedTest
    @EnumSource( TYPES.class )
    public void testStringEncryption(TYPES type) {
        cryptoUtilJ8s.add(CryptoUtilJ8.getInstance(type));
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
     * @throws Exception Generic exception
     */
    @ParameterizedTest
    @EnumSource( TYPES.class )
    public void testStringHandling(TYPES type)  {
        cryptoUtilJ8s.add(CryptoUtilJ8.getInstance(type));
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

    /** Test creating a password
     * @throws Exception Generic exception
     */
    @Test
    public void testPasswordFactory() throws Exception {
        char[] result = null;
        result = PasswordFactory.getInstance("SHA-256").create();
        System.out.println("random pw:" + new String(result));
        result = PasswordFactory.getInstance("SHA-256",10_000).create(this.getPassword());
        System.out.println("password pw with seed:" + new String(result));
        assertNotNull(result);
        return;
    }
    
    /** Test encryption and decryption of binary data
     * @throws Exception Generic exception
     */
    @ParameterizedTest
    @EnumSource( TYPES.class )
    public void testBinaryHandling(TYPES type) throws Exception {
        cryptoUtilJ8s.add(CryptoUtilJ8.getInstance(type));
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
    
    /** Test encryption and decryption of Strings 
     * @throws Exception Generic exception
     */
    @ParameterizedTest
    @EnumSource( TYPES.class )
    public void testStringWithPasswordEncryption(TYPES type) {
        char[] password = "57cb-4a23-d838-45222".toCharArray();
        String source = "e02c-3b76-ff1e-5d9a1";
        cryptoUtilJ8s.add(CryptoUtilJ8.getInstance(type));
        cryptoUtilJ8s.forEach(cuj8 -> { 
            System.out.println("checking "+ cuj8.getType());
            String cipherText = null;
            try {
                cipherText = cuj8.encryptString(source, password);
                System.out.println(cipherText);// about 128
                
                System.out.println("length for " + cuj8.getType() + " is:" +cipherText.length());// about 128
                if (cuj8.type == TYPES.PBE) {
                    assertEquals(128, cipherText.length()); // 128bytes + 10 bytes for cleartext
                } 
                CryptoStreamFactoryJ8Template.setInstance(null);
                String plainText = cuj8.decryptString(cipherText, password);
                assertEquals(source, plainText);
            } catch (GeneralSecurityException | IOException e) {
                e.printStackTrace();
                fail();
            }
            
        });      

    }

}
