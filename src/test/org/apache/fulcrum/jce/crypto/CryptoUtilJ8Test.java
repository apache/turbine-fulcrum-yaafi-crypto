package org.apache.fulcrum.jce.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.File;

import org.junit.Before;
import org.junit.Test;


/**
 * Test suite for crypto functionality
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl</a>
 */

public class CryptoUtilJ8Test {
    /** the password to be used */
    private String password;

    /** the test data directory */
    private File testDataDirectory;

    /** the temp data director */
    private File tempDataDirectory;
    
    private CryptoUtilJ8 cryptoUtilJ8;

    /**
     * Constructor
     */
    public CryptoUtilJ8Test() {

        this.password = "mysecret";
        this.testDataDirectory = new File("./src/test/data");
        this.tempDataDirectory = new File("./target/temp");
        this.tempDataDirectory.mkdirs();
    }

    /**
     * @see junit.framework.TestCase#setUp() byte[] salt, int count, String
     *      algorithm, String providerName )
     * 
     * @throws Exception Generic exception
     */
    @Before
    public void setUp() throws Exception {
        cryptoUtilJ8 = CryptoUtilJ8.getInstance();
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
     * @throws Exception Generic exception
     */
    @Test
    public void testTextEncryption() throws Exception {
        File sourceFile = new File(this.getTestDataDirectory(), "plain.txt");
        File targetFile = new File(this.getTempDataDirectory(), "plain.j8.enc.txt");
        cryptoUtilJ8.encrypt(sourceFile, targetFile, this.getPassword());
    }

    /** Decrypt a text file 
     * @throws Exception Generic exception
     */
    @Test
    public void testTextDecryption() throws Exception {
        testTextEncryption();
        File sourceFile = new File(this.getTempDataDirectory(), "plain.j8.enc.txt");
        File targetFile = new File(this.getTempDataDirectory(), "plain.j8.dec.txt");
        cryptoUtilJ8.decrypt(sourceFile, targetFile.getAbsolutePath(), this.getPassword());
    }
    
    /** Encrypt a PDF file 
     * 
     * @throws Exception Generic exception
     */
    @Test
    public void testPdfEncryption() throws Exception {
        File sourceFile = new File(this.getTestDataDirectory(), "plain.pdf");
        File targetFile = new File(this.getTempDataDirectory(), "plain.j8.enc.pdf");
        cryptoUtilJ8.encrypt(sourceFile, targetFile, this.getPassword());
    }

    /** Decrypt a PDF file 
     * 
     * @throws Exception Generic exception
     */
    @Test
    public void testPdfDecryption() throws Exception {
        testPdfEncryption();
        File sourceFile = new File(this.getTempDataDirectory(), "plain.j8.enc.pdf");
        File targetFile = new File(this.getTempDataDirectory(), "plain.j8.dec.pdf");
        cryptoUtilJ8.decrypt(sourceFile, targetFile, this.getPassword());
    }

    /** Test encryption and decryption of Strings
     * 
     *  @throws Exception Generic exception
     */
    @Test
    public void testStringEncryption() throws Exception {
        char[] testVector = new char[513];

        for (int i = 0; i < testVector.length; i++) {
            testVector[i] = (char) i;
        }

        String source = new String(testVector);
        String cipherText = cryptoUtilJ8.encryptString(source, this.getPassword());
        String plainText = cryptoUtilJ8.decryptString(cipherText, this.getPassword());
        assertEquals(source, plainText);
    }

    /** Test encryption and decryption of Strings
     * @throws Exception Generic exception
     */
    @Test
    public void testStringHandling() throws Exception {
        String source = "Nobody knows the toubles I have seen ...";
        String cipherText = cryptoUtilJ8.encryptString(source, this.getPassword());
        String plainText = cryptoUtilJ8.decryptString(cipherText, this.getPassword());
        assertEquals(source, plainText);
    }

    /** Test creating a password
     * @throws Exception Generic exception
     */
    @Test
    public void testPasswordFactory() throws Exception {
        char[] result = null;
        result = PasswordFactory.getInstance("SHA-256").create();
        System.out.println(new String(result));
        result = PasswordFactory.getInstance("SHA-256",10_000).create(this.getPassword());
        System.out.println(new String(result));
        assertNotNull(result);
        return;
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

        cryptoUtilJ8.encrypt(source, cipherText, this.getPassword());
        cryptoUtilJ8.decrypt(cipherText, plainText, this.getPassword());

        result = plainText.toByteArray();

        for (int i = 0; i < source.length; i++) {
            if (source[i] != result[i]) {
                fail("Binary data are different at position " + i);
            }
        }
    }
    
    /** Test encryption and decryption of Strings 
     * @throws Exception Generic exception
     */
    @Test
    public void testStringWithPasswordEncryption() throws Exception {
        char[] password = "57cb-4a23-d838-45222".toCharArray();
        String source = "e02c-3b76-ff1e-5d9a1";
        String cipherText = cryptoUtilJ8.encryptString(source, password);
        System.out.println(cipherText);// 128bit
        assertEquals(128, cipherText.length());
        CryptoStreamFactoryJ8Impl.setInstance(null);
        String plainText = cryptoUtilJ8.decryptString(cipherText, password);
        assertEquals(source, plainText);
    }

}
