package org.apache.fulcrum.jce.crypto.extended;

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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.fulcrum.jce.crypto.CryptoStreamFactory;
import org.apache.fulcrum.jce.crypto.CryptoUtil;
import org.apache.fulcrum.jce.crypto.StreamUtil;
import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8.TYPES;

/**
 * Helper class to provide typed functions to work with CryptoStreams.
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl </a>
 * @author <a href="mailto:gk@apache.org">Georg Kallidis</a>
 */
public final class CryptoUtilJ8 extends CryptoUtil {

	/** the typed default instances */   
    private static final Map<TYPES, CryptoUtilJ8> instances = new ConcurrentHashMap<>();
    
    /** the default instances with custom settings **/
    private static final Map<TYPES, CryptoUtilJ8> instancesWithExplicitParams = new ConcurrentHashMap<>();    
	
	/**
	 * Factory method to get a default instance
	 * 
	 * default type PDC
	 * 
	 * @return an instance of the CryptoStreamFactory
	 */
	public static CryptoUtilJ8 getInstance() {
		synchronized (CryptoUtilJ8.class) {
			TYPES defaultType = CryptoParametersJ8.DEFAULT_TYPE;
			if (instances.isEmpty() || !instances.containsKey(defaultType)) {
				instances.put(defaultType, new CryptoUtilJ8());
			}
			return instances.get(defaultType);
		}
	}
	
	/**
	 * Factory method to get a default instance
	 * 
	 * @param type one of the enum {@link TYPES}.
	 * @return an instance of the CryptoStreamFactory
	 */
	public static CryptoUtilJ8 getInstance(TYPES type) {
		synchronized (CryptoUtilJ8.class) {
			if (!instances.containsKey(type)) {
				instances.put(type, new CryptoUtilJ8(type));
			}
			return instances.get(type);
		}
	}
	
	/**
	 * Factory method to get a default instance
	 * 
	 * @param type one of the enum {@link TYPES}.
	 * @param salt the salt
	 * @param count the iteration count
	 * @return an instance of the CryptoStreamFactory
	 */
	public static CryptoUtilJ8 getInstance(TYPES type, byte[] salt, int count) {
		synchronized (CryptoUtilJ8.class) {
			if (!instancesWithExplicitParams.containsKey(type)) {
				instancesWithExplicitParams.put(type, new CryptoUtilJ8(type, salt, count));
			}
			return instancesWithExplicitParams.get(type);
		}
	}
	
	private CryptoUtilJ8() {
		cryptoStreamFactory = CryptoStreamFactoryJ8Template.getInstance();
	}
	
	private CryptoUtilJ8(TYPES type) {
		cryptoStreamFactory = CryptoStreamFactoryJ8Template.getInstance(type);
	}
	
    /**
     * 
     * @param type one of the enum {@link TYPES}.
     * @param salt v
     * @param count the iteration count
     */
    protected CryptoUtilJ8(TYPES type, byte[] salt, int count) {
    	cryptoStreamFactory = CryptoStreamFactoryJ8Template.getInstance(type, salt, count);
    }

	/**
	 * Copies from a source to a target object using encryption and a caller
	 * supplied CryptoStreamFactory.
	 * 
	 * {@link CryptoStreamFactoryJ8Template#getOutputStream(InputStream, OutputStream, char[])} 
	 *
	 * @param factory  the factory to create the crypto streams
	 * @param source   the source object
	 * @param target   the target object
	 * @param password the password to use for encryption
	 * @throws GeneralSecurityException accessing JCE failed
	 * @throws IOException              accessing the source failed
	 */
	@Override
	public void encrypt(CryptoStreamFactory factory, Object source, Object target, char[] password)
			throws GeneralSecurityException, IOException {
		InputStream is = StreamUtil.createInputStream(source);
		OutputStream os = StreamUtil.createOutputStream(target);
		((CryptoStreamFactoryJ8) factory).getOutputStream(is, os, password);
	}

	/**
	 * Copies from a source to a target object using decryption and a caller-suppier
	 * CryptoStreamFactory.
	 *
	 * @param factory  the factory to create the crypto streams
	 * @param source   the source object
	 * @param target   the target object
	 * @param password the password to use for decryption
	 * @throws GeneralSecurityException accessing JCE failed
	 * @throws IOException              accessing the source failed
	 */
	@Override
	protected void decrypt(CryptoStreamFactory factory, Object source, Object target, char[] password)
			throws GeneralSecurityException, IOException {
		InputStream is = StreamUtil.createInputStream(source);
		OutputStream os = StreamUtil.createOutputStream(target);
		InputStream dis = factory.getInputStream(is, password);
		StreamUtil.copy(dis, os);
	}

	public static Map<TYPES, CryptoUtilJ8> getInstances() {
		return instances;
	}

	public static Map<TYPES, CryptoUtilJ8> getInstancesWithExplicitParams() {
		return instancesWithExplicitParams;
	}

}
