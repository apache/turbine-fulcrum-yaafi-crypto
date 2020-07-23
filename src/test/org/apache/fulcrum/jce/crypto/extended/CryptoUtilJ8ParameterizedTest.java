package org.apache.fulcrum.jce.crypto.extended;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8.TYPES;
import org.apache.fulcrum.jce.junit5.extension.SupportedTypeArguments;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

/**
 * Test suite for crypto functionality
 * 
 * Could still not access arguments of parameterized tests in lifecycle callback methods
 * 
 * - https://github.com/junit-team/junit5/issues/944
 * - https://github.com/junit-team/junit5/issues/1139#issuecomment-341683075
 *
 * e.g. with ExtendWith(SupportedTypeArguments.class)
 * */
public class CryptoUtilJ8ParameterizedTest {
	/** the password to be used */
	private String password;

	/** the test data directory */
	private File testDataDirectory;

	/** the temp data director */
	private File tempDataDirectory;

	private List<CryptoUtilJ8> cryptoUtilJ8s = new ArrayList<>();

	private static Logger log = LogManager.getLogger(CryptoUtilJ8ParameterizedTest.class);

	/**
	 * Constructor
	 */
	public CryptoUtilJ8ParameterizedTest() {
		this.password = "mysecret";
		this.testDataDirectory = new File("./src/test/data");
		this.tempDataDirectory = new File("./target/temp");
		this.tempDataDirectory.mkdirs();
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

	@BeforeEach
	public void setup() {
		cryptoUtilJ8s.clear();
        SupportedTypeArguments.init();
	}
	

	@AfterEach
	public void clean() {
		cryptoUtilJ8s.clear();
	}

	/**
	 * Parameterized Test
	 * 
	 * Encrypt a text file
	 * 
	 * @param type the type to be tested based on {@link TYPES}
	 * 
	 */
	@ParameterizedTest
	@ArgumentsSource(SupportedTypeArguments.class)
	public void testTextEncryption(TYPES type) {

		cryptoUtilJ8s.add(CryptoUtilJ8.getInstance(type));
		File sourceFile = new File(this.getTestDataDirectory(), "plain.txt");
		File targetFile = new File(this.getTempDataDirectory(), "plain.j8.enc.txt");

		cryptoUtilJ8s.forEach(cuj8 -> {
			try {
				log.debug("registered {}: {}", cuj8.getClass().getSimpleName());
	            CryptoStreamFactoryJ8Template crt = ((CryptoStreamFactoryJ8Template)cuj8.getCryptoStreamFactory());
	            log.debug(String.format("created default crypto factory instance %s for algo %s with salt (optional): %s", 
	            		crt.getClass().getSimpleName(),
           		crt.getAlgorithm(), crt.getSalt()));
				cuj8.encrypt(sourceFile, targetFile, this.getPassword());
			} catch (GeneralSecurityException e) {
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				e.printStackTrace();
				fail();
			}
		});
	}

	/**
	 * Parameterized Test Decrypt a text file
	 * 
	 * @param type the type to be tested based on {@link TYPES}
	 * 
	 */
	@ParameterizedTest
	@ArgumentsSource(SupportedTypeArguments.class)
	public void testTextDecryption(TYPES type) {
		cryptoUtilJ8s.add(CryptoUtilJ8.getInstance(type));
		cryptoUtilJ8s.forEach(cuj8 -> {
			log.debug("registered {}: {}", cuj8.getClass().getSimpleName());
            CryptoStreamFactoryJ8Template crt = ((CryptoStreamFactoryJ8Template)cuj8.getCryptoStreamFactory());
            log.debug(String.format("created default crypto factory instance %s for algo %s with salt length: %s", 
               		crt.getClass().getSimpleName(),
               		crt.getAlgorithm(), crt.getSalt().length));
			try {
				File sourceFile = new File(this.getTestDataDirectory(), "plain.txt");
				File targetFile = new File(this.getTempDataDirectory(), "plain.j8.enc.txt");
				cuj8.encrypt(sourceFile, targetFile, this.getPassword());

				File sourceFile2 = targetFile;
				File targetFile2 = new File(this.getTempDataDirectory(), "plain.j8.dec.txt");
				cuj8.decrypt(sourceFile2, targetFile2.getAbsolutePath(), this.getPassword());
				assertEquals(new String(Files.readAllBytes(Paths.get(sourceFile.toURI()))),
						new String(Files.readAllBytes(Paths.get(targetFile2.toURI()))));
			} catch (GeneralSecurityException | IOException e) {
				e.printStackTrace();
				fail();
			}
		});
	}

	/**
	 * Parameterized Test
	 * 
	 * Encrypt a PDF file
	 * 
	 * @param type the type to be tested based on {@link TYPES}
	 * 
	 */
	@ParameterizedTest
	@ArgumentsSource(SupportedTypeArguments.class)
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

	/**
	 * Parameterized Test Decrypt a PDF file
	 *
	 * @param type the type to be tested based on {@link TYPES}
	 * 
	 */
	@ParameterizedTest
	@ArgumentsSource(SupportedTypeArguments.class)
	public void testPdfDecryption(TYPES type) {
		cryptoUtilJ8s.add(CryptoUtilJ8.getInstance(type));
		// testPdfEncryption();
		cryptoUtilJ8s.forEach(cuj8 -> {
			try {
				File sourceFile = new File(this.getTestDataDirectory(), "plain.pdf");
				File targetFile = new File(this.getTempDataDirectory(), "plain.j8.enc.pdf");
				cuj8.encrypt(sourceFile, targetFile, this.getPassword());

				File sourceFile2 = targetFile;
				File targetFile2 = new File(this.getTempDataDirectory(), "plain.j8.dec.pdf");
				cuj8.decrypt(sourceFile2, targetFile2, this.getPassword());

				assertEquals(new String(Files.readAllBytes(Paths.get(sourceFile.toURI()))),
						new String(Files.readAllBytes(Paths.get(targetFile2.toURI()))));
			} catch (GeneralSecurityException | IOException e) {
				e.printStackTrace();
				fail();
			}
		});

	}

	/**
	 * Parameterized Test Test encryption and decryption of Strings
	 * 
	 * @param type the type to be tested based on {@link TYPES}
	 * 
	 */
	@ParameterizedTest
	@ArgumentsSource(SupportedTypeArguments.class)
	public void testStringEncryption(TYPES type) {
		CryptoUtilJ8 cuj8 = CryptoUtilJ8.getInstance(type);
		
		log.debug("registered {} and called for {}", cuj8.getClass().getSimpleName(), type);
        CryptoStreamFactoryJ8Template crt = ((CryptoStreamFactoryJ8Template)cuj8.getCryptoStreamFactory());
        log.debug(String.format("created default crypto factory instance %s for algo %s with salt length: %s", 
           		crt.getClass().getSimpleName(),
           		crt.getAlgorithm(), crt.getSalt().length));
		char[] testVector = new char[513];

		for (int i = 0; i < testVector.length; i++) {
			testVector[i] = (char) i;
		}

		String source = new String(testVector);
		String cipherText = null;
		String plainText = null;
		try {
			log.info("Test without clearTextHeader in type {}", type);
			cipherText = cuj8.encryptString(source, this.getPassword());
			log.trace(cipherText);
			plainText = cuj8.decryptString(cipherText, this.getPassword());
			assertEquals(source, plainText, source + " is not equal with " + plainText);
			
			String clearCode = type.equals(TYPES.PBE)? CryptoParametersJ8.TYPES.PBE.getClearCode():
				CryptoParametersJ8.TYPES.GCM.getClearCode() ;

			log.info(String.format("Test with clearTextHeader %s in encrypted string.",clearCode) );
			String cipherText2 = cuj8.encryptStringWithClearCode(source, this.getPassword());
			log.trace(cipherText2);
			assertTrue(cipherText2.startsWith(clearCode),
					String.format("%s does not start with '%s'", cipherText2, clearCode));
			String plainText2 = cuj8.decryptStringWithClearCode(cipherText2, this.getPassword());
			assertEquals(source, plainText2, String.format("%s is not equal with %s", source, plainText));

		} catch (GeneralSecurityException | IOException e) {
			e.printStackTrace();
			fail();
		}
	}

	/**
	 * Parameterized Test Test encryption and decryption of Strings
	 * 
	 * @param type the type to be tested based on {@link TYPES}
	 * 
	 */
	@ParameterizedTest
	@ArgumentsSource(SupportedTypeArguments.class)
	public void testStringHandling(TYPES type) {
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

	/**
	 * Test creating a password
	 * 
	 * @throws Exception Generic exception
	 */
	@Test
	public void testPasswordFactory() throws Exception {
		char[] result = null;
		result = PasswordFactory.getInstance("SHA-256").create();
		log.info("random pw:" + new String(result));
		result = PasswordFactory.getInstance("SHA-256", 10_000).create(this.getPassword());
		log.info("password pw with seed:" + new String(result));
		assertNotNull(result);
		return;
	}

	/**
	 * Parameterized Test
	 * 
	 * Test encryption and decryption of binary data
	 * 
	 * @throws Exception Generic exception
	 * 
	 * @param type the type to be tested based on {@link TYPES}
	 */
	@ParameterizedTest
	@ArgumentsSource(SupportedTypeArguments.class)
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

	/**
	 * Parameterized Test
	 * 
	 * Test encryption and decryption of Strings
	 * 
	 * @param type the type to be tested based on {@link TYPES}
	 * 
	 */
	@ParameterizedTest
	@ArgumentsSource(SupportedTypeArguments.class)
	public void testStringWithPasswordEncryption(TYPES type) {
		char[] password = "57cb-4a23-d838-45222".toCharArray();
		String source = "e02c-3b76-ff1e-5d9a1";
		CryptoUtilJ8 cuj8 = CryptoUtilJ8.getInstance(type);
		log.debug("registered {}: {}", cuj8.getClass().getSimpleName());
        CryptoStreamFactoryJ8Template crt = ((CryptoStreamFactoryJ8Template)cuj8.getCryptoStreamFactory());
        log.debug(String.format("created default crypto factory instance %s for algo %s with salt (optional): %s", 
       		crt.getClass().getSimpleName(),
       		crt.getAlgorithm(), crt.getSalt()));
		String cipherText = null;
		try {
			cipherText = cuj8.encryptString(source, password);
			log.info(cipherText);// about 128
			log.info(String.format("length for %s is %d", cuj8, cipherText.length()));// about 128
			assertEquals(128, cipherText.length());
//			if (cuj8.type == TYPES.PBE) {
//				assertEquals(128, cipherText.length()); // 128bytes + 10 bytes for cleartext
//			}
//			if (cuj8.type == TYPES.GCM) {
//				assertEquals(128, cipherText.length());
//			}
			String plainText = cuj8.decryptString(cipherText, password);
			assertEquals(source, plainText);
		} catch (GeneralSecurityException | IOException e) {
			e.printStackTrace();
			fail();
		}
	}

}
