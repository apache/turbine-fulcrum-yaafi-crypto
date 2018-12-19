package org.apache.fulcrum.jce.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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
//        CryptoStreamFactoryImpl factory = new CryptoStreamFactoryJ8Impl(CryptoParameters.SALT, CryptoParameters.COUNT_J8);
//
//        CryptoStreamFactoryImpl.setInstance(factory);
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
        CryptoUtilJ8.getInstance().encrypt(sourceFile, targetFile, this.getPassword());
    }

    /** Decrypt a text file 
     * @throws Exception Generic exception
     */
    @Test
    public void testTextDecryption() throws Exception {
        testTextEncryption();
        File sourceFile = new File(this.getTempDataDirectory(), "plain.j8.enc.txt");
        File targetFile = new File(this.getTempDataDirectory(), "plain.j8.dec.txt");
        CryptoUtilJ8.getInstance().decrypt(sourceFile, targetFile.getAbsolutePath(), this.getPassword());
    }
    
    /** Encrypt a PDF file 
     * 
     * @throws Exception Generic exception
     */
    @Test
    public void testPdfEncryption() throws Exception {
        File sourceFile = new File(this.getTestDataDirectory(), "plain.pdf");
        File targetFile = new File(this.getTempDataDirectory(), "plain.j8.enc.pdf");
        CryptoUtil.getInstance().encrypt(sourceFile, targetFile, this.getPassword());
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
        CryptoUtil.getInstance().decrypt(sourceFile, targetFile, this.getPassword());
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

    /** Test encryption and decryption of Strings 
     * @throws Exception Generic exception
     */
    @Test
    public void testStringWithPasswordEncryption() throws Exception {
        char[] password = "57cb-4a23-d838-45222".toCharArray();
        String source = "e02c-3b76-ff1e-5d9a1";
        String cipherText = CryptoUtilJ8.getInstance().encryptString(source, password);
        System.out.println(cipherText);// 128bit
        assertEquals(128, cipherText.length());
        //CryptoStreamFactoryJ8Impl.setInstance(null);
        String plainText = CryptoUtilJ8.getInstance().decryptString(cipherText, password);
        assertEquals(source, plainText);
    }

}
