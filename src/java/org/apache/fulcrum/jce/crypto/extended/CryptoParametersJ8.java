package org.apache.fulcrum.jce.crypto.extended;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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
 * CryptoParameters used for encryption/decryption.
 *
 * @author <a href="mailto:gk@apache.org">Georg Kallidis</a>
 */

public interface CryptoParametersJ8 {
	
	/**
	 * 
	 * Implementing classes are either using
	 * 
	 * <ul>
	 * <li>PBEWith &lt;digest&gt;And&lt;encryption&gt; - the password-based encryption algorithm defined in PKCS #5: PBEWithHmacSHA256AndAES_256/CBC/PKCS5Padding in {@link #ALGORITHM_J8_PBE}</li>
	 * </ul>
	 * 
	 * or
	 * 
	 * <ul>
	 * <li>AES/GCM/NoPadding in {@link #ALGORITHM_J8_GCM} (Cipher Algorithm Names/Cipher Algorithm Modes/Cipher Algorithm Padding). Cipher is Galois/Counter Mode, as defined in NIST Special Publication SP 800-38D: </li>
	 * </ul>
	 * 
	 * 
	 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunJCEProvider">The Oracle Security SunJCE Provider</a>
	 * 
	 * Algo/mode/padding for cipher transformation:
	 * 
	 * Java 8: <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher">The Oracle Security Standard Names Cipher Algorithms</a>
	 * 
	 * Java 14: <a href="https://docs.oracle.com/en/java/javase/14/docs/specs/security/standard-names.html#security-algorithm-implementation-requirements">Security Algorithm Implementation Requirements</a>
	 * 
	 */
	public enum TYPES_IMPL {
		
		// key size 256
		ALGORITHM_J8_PBE("PBEWithHmacSHA256AndAES_256"), 
		// key size 128
		ALGORITHM_J8_GCM("AES_128/GCM/NoPadding");

		private final String algorithm;

		private TYPES_IMPL(String algo) {
			algorithm = algo;
		}

		@Override
		public String toString() {
			return this.algorithm;
		}

		public String getAlgorithm() {
			return algorithm;
		}
		
		/**
		 * clear code depending on algorithm AES size return <pre>J8AESAES_&lt;size&gt;;</pre>.
		 * {@link CryptoParametersJ8#CLEAR_CODE_DEFAULT}
		 *  
		 * @return clear code J8AES_&lt;size&gt;; with three digit size.
		 */
		public String getClearCode() {
			
			return String.format("J8%1$s;", 
					algorithm.subSequence(algorithm.indexOf("AES_"),algorithm.indexOf("AES_")+7));
		}
	}

	/**
	 * 
	 * short names, exact names @see {@link TYPES_IMPL}.
	 *
	 */
	public enum TYPES {
		
		/**
		 *  PBE algorithm is kind of meta algorithm, uses AES, see above. 
		 */
		PBE, 
		/**
		 *  AES algorithm, but GCM is is actually the algorithm mode, but nevertheless used as a short name.
		 */
		GCM;

		/**
		 * Clear code should be always 10 bytes.
		 * 
		 * {@link CryptoParametersJ8#CLEAR_CODE_DEFAULT}
		 * 
		 * @return clear code
		 * 
		 */
		public String getClearCode() {
			return this.equals(TYPES.PBE)? 
					TYPES_IMPL.ALGORITHM_J8_PBE.getClearCode():
				TYPES_IMPL.ALGORITHM_J8_GCM.getClearCode();
		}
	}

	/**
	 * Prefix to decrypted hex hash to get a clue, what to use and what it is; should be always 10 bytes.
	 */
	public String CLEAR_CODE_DEFAULT = "J8_AES064;";
	
	public TYPES DEFAULT_TYPE = TYPES.PBE;

	
	/**
	 * Checks Java provider with <b>type</b> has exact type or contains any of the strings in algoList.
	 * <pre>Types</pre> may be Cipher, AlgorithmParameters, KeyGenerator, Alg, Mac, SecretKeyFactory.
	 * 
	 * @param algoList the types to be checked
	 * @param type the type is ignored if not exact, instead uses the two types: "AlgorithmParameters", "Cipher".
	 * @param exact if exact does a exact match 
	 * @return the matched results as a list or emtpy list
	 */
	public static List<String> getSupportedAlgos(List<String> algoList, String type, boolean exact) {
		List<String> result = new ArrayList<String>();
		Provider p[] = Security.getProviders();
		List<Provider> providerList = Arrays.asList(p);

		for (Provider provider : providerList) {
			//System.out.println(provider);
			result.addAll(Collections.list(provider.keys()).stream().map(t -> t.toString())
					.filter(x->
							(exact)? 
							(x.startsWith(type) && algoList.contains(x.replaceAll(type + ".", ""))):
							(x.matches("(" +String.join("|", PROVIDER_TYPES) + ").*$") && 
									algoList.stream().anyMatch(y -> y.contains(x.replaceAll(type + ".", "")))
							)
					)
					.map( x ->
					(exact)? 
					   x.replaceAll(type + ".", ""):
						   x.replaceAll("(" +String.join("|", PROVIDER_TYPES) + ")" + ".", "")
					)
					.collect(Collectors.toList()));
		}
		return result;
	}
	
	public static List[] LISTS = {  Arrays.stream(CryptoParametersJ8.TYPES.values()).map(t -> t.toString())
			.collect(Collectors.toList()), 
					Arrays.stream(CryptoParametersJ8.TYPES_IMPL.values()).map(t -> t.toString())
					.collect(Collectors.toList()) };
	
	public static String[] PROVIDER_TYPES = { "AlgorithmParameters", "Cipher" };

	/**
	 * initializes supported parameters by filtering {@link TYPES} against <i>AlgorithmParameters</i> in system supported cipher suites:
	 * first by an exact match with type <i>AlgorithmParameters</i>, then by inexact matching.
	 * 
	 * {@link #getSupportedAlgos(List, String, boolean)}
	 * @return list of supported algo short codes, if nothing is found, the list is empty.
	 */
	static List<String> init() {
		List<String> result = new ArrayList<String>();
		List<String> defaultSupportedTypes = LISTS[0];
		String providerType = PROVIDER_TYPES[0];
		result = getSupportedAlgos(defaultSupportedTypes, providerType, true);
		// no duplicates
		Set<String> resultSet = new LinkedHashSet<String>(result);
		resultSet.addAll( getSupportedAlgos(defaultSupportedTypes, providerType, false));

		List<String> algoList = LISTS[1];
		String type = PROVIDER_TYPES[1];
		List<String> result3 = CryptoParametersJ8.getSupportedAlgos(algoList, type, true);
		defaultSupportedTypes.stream().forEach(c-> {
			if (result3.stream().anyMatch(x -> x.contains(c))) {
				//System.out.println("adding " + c);
				resultSet.add(c);
			}
		});
		return new ArrayList<>(resultSet);
	}

}
