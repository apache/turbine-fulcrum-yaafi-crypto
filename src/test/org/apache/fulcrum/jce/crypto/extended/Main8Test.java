package org.apache.fulcrum.jce.crypto.extended;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.fulcrum.jce.crypto.cli.CLI2;
import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8.TYPES;
import org.apache.fulcrum.jce.junit5.extension.SupportedTypeArguments;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;
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

public class Main8Test {
	/** the password to be used */
	private String password;

	/**
	 * Constructor
	 */
	public Main8Test() {

		this.password = "foobar";
		ConfigurationBuilder<BuiltConfiguration> builder = ConfigurationBuilderFactory.newConfigurationBuilder();
		builder.setStatusLevel(Level.DEBUG);
	}

	@BeforeAll
	public static void setup() {
		SupportedTypeArguments.init();
	}

	/**
	 * @return Returns the password.
	 */
	protected char[] getPassword() {
		return password.toCharArray();
	}

	/** Encrypt a string on the command line */
	@Test
	public void testStringEncryption() {
		String[] encryptionArgs = { "string", "enc", this.password, "mysecretpassword" };
		CLI2.main(encryptionArgs);
		String[] decryptionArgs = { "string", "dec", this.password,
				"ce3bf02da8a57c94b4f42c084230d1bedcd856c49a3fd23ec59835ca46a3d37ee02d470394691353478c905e7b342316d1fcc3e1b98837bf0595ef50853922df" };
		CLI2.main(decryptionArgs);
	}

	@Test
	public void testAnotherStringEncryption() {
		String[] encryptionArgs = { "string", "enc", this.password, "secret" };
		CLI2.main(encryptionArgs);
		String[] decryptionArgs = { "string", "dec", this.password,
				"8626904c9e64fddfa64add56472c4796429b0adb7c8039424adef7434be6bc255ce092011e8c560965814e806dd68117" };
		CLI2.main(decryptionArgs);
	}

	@Test
	/** Encrypt a text file on the command line */
	public void testFileEncryption1() {
		String[] encryptionArgs = { "file", "enc", this.password, "./src/test/data/plain.txt",
				"./target/main8/plain.enc.txt" };
		String[] decryptionArgs = { "file", "dec", this.password, "./target/main8/plain.enc.txt",
				"./target/main8/plain.dec.txt" };
		CLI2.main(encryptionArgs);
		CLI2.main(decryptionArgs);
		try {
			assertTrue(FileUtils.contentEquals(new File("./src/test/data/plain.txt"),
					new File("./target/main8/plain.dec.txt")));
		} catch (IOException e) {
			fail();
		}
	}

	@Test
	/** Encrypt a text file in-place on the command line */
	public void testFileEncryption2() {
		String[] encryptionArgs = { "file", "enc", this.password, "./src/test/data/plain.txt",
				"./target/main8/plain.txt" };
		// caution decrypting into source file!
		String[] decryptionArgs = { "file", "dec", this.password, "./target/main8/plain.txt" };
		CLI2.main(encryptionArgs);
		CLI2.main(decryptionArgs);
	}

	@Test
	public void testYetAnotherStringEncryption() {
		try {
			// assumptions
			String topSecret = "mysecretpassword";
			assertTrue(FileUtils.readFileToString(new File("./src/test/data/plain-simple.txt"), StandardCharsets.UTF_8)
					.equals(topSecret));

			if (SupportedTypeArguments.SUPPORTED_TYPES.contains(TYPES.GCM.toString())) {

				// test
				// encode from string = hexdecimal file
				String[] encryptionArgs = { "string", "enc" + TYPES.GCM, this.password, topSecret,
						"./target/main8/another-plain16chars.enc.txt" };
				CLI2.main(encryptionArgs);
				// shows hex dec in stderr + file

				String[] decryptionArgs = { "string", "dec" + TYPES.GCM, this.password,
						"c9fa3e7d3c49d379ee8ff2dff6e6effbafee264794a03d0ffd895caac2b3c9b4558087f5b12e72a92475f1ed638b7911389234b443d4ebcf351c86cb",
						"./target/main8/another-plain16chars.dec.txt" };
				CLI2.main(decryptionArgs);
				// shows clear password in stdout + file

				assertTrue(FileUtils.readFileToString(new File("./target/main8/another-plain16chars.dec.txt"),
						StandardCharsets.UTF_8).equals(topSecret));

				String[] decryptionArgs2 = { "string", "dec" + TYPES.GCM, this.password,
						"605efd3009a7242a9c9cab23aa712d6d116e8686732194d3306416cda2a416df1e63aeffcdc1910af1e1100b382b24fc628d9c413ebf7e1b2885c0ec" };
				CLI2.main(decryptionArgs2);
				// shows clear password in stdout (offline decoded)

				// file mode commands do show nothing on stdout, except Decrypting / Encrypting

				// should not fail, if converted from hex
				String[] decryptionArgs3 = { "file", "dec" + TYPES.GCM, this.password,
						"./target/main8/another-plain16chars.enc.txt", "./target/main8/another-plain16chars2.dec.txt" };
				CLI2.main(decryptionArgs3);
				assertTrue(FileUtils.readFileToString(new File("./target/main8/another-plain16chars2.dec.txt"),
						StandardCharsets.UTF_8).equals(topSecret));

				String[] encryptionArgs4 = { "file", "enc" + TYPES.GCM, this.password,
						"./src/test/data/plain-simple.txt", "./target/main8/plain-simple.enc.txt" };
				CLI2.main(encryptionArgs4);

				String[] decryptionArgs4 = { "file", "dec" + TYPES.GCM, this.password,
						"./target/main8/plain-simple.enc.txt", "./target/main8/plain-simple.dec.txt" };
				CLI2.main(decryptionArgs4);

				try {
					assertTrue(FileUtils.contentEquals(new File("./src/test/data/plain-simple.txt"),
							new File("./target/main8/plain-simple.dec.txt")));
				} catch (IOException e) {
					fail();
				}

			}

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testIntegratedStringEncryption() {
		try {
			// assumptions
			String topSecret = "myX!_secretp@ssword?~,2";

			Map<String, Object> conf = new HashMap<>();
			conf.put("enc", TYPES.GCM);

			// encode as string to stderr and file in hexdecimal format
			String[] encryptionArgs = { "string", "enc" + conf.get("enc"), this.password, topSecret,
					"./target/main8/integrated-plain16chars.enc.txt" };
			CLI2.main(encryptionArgs);
			// shows encoded hexdec in stdout + file

			String encodedEncrypted = FileUtils.readFileToString(
					new File("./target/main8/integrated-plain16chars.enc.txt"), StandardCharsets.UTF_8);

			conf.put("pw", encodedEncrypted);

			// this should be done without output to console
			String result = CLI2.processString("dec" + conf.get("enc"), this.password.toCharArray(),
					(String) conf.get("pw"));

			assertTrue(result.equals(topSecret));

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	@Test
    public void testDefaultStringEncryption() {
        char[] testVector = new char[513];

        for (int i = 0; i < testVector.length; i++) {
            testVector[i] = (char) i;
        }
        String source = new String(testVector);
       
        CryptoUtilJ8.getInstances().clear();
        CryptoUtilJ8 cuj8 = CryptoUtilJ8.getInstance();
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
    }

}