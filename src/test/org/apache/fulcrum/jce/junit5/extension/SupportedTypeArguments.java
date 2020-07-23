package org.apache.fulcrum.jce.junit5.extension;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8;
import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8.TYPES;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;

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
 * Using {@link CryptoParametersJ8#init()} and ArgumentsProvider to filter parameters.
 * 
 * Could still not access arguments of parameterized tests in lifecycle callback methods
 * 
 * - https://github.com/junit-team/junit5/issues/944
 * - https://github.com/junit-team/junit5/issues/1139#issuecomment-341683075
 * 
 * @author gkallidis
 *
 */
public class SupportedTypeArguments implements ArgumentsProvider {
	
	public static Logger log = LogManager.getLogger();
	
	public static List<String> SUPPORTED_TYPES = null;
	
	public static void init() {
		if (SUPPORTED_TYPES == null) {
			SUPPORTED_TYPES = CryptoParametersJ8.init();
		}
		log.warn("SUPPORTED_TYPES: {}",SupportedTypeArguments.SUPPORTED_TYPES);
	}
 
	@Override
	public Stream<? extends Arguments> provideArguments(ExtensionContext arg0) throws Exception {
		if (SUPPORTED_TYPES == null) {
			init();
		}
		return SUPPORTED_TYPES.stream().map(Arguments::of);
	}

	public static List<String> getSUPPORTED_TYPES() {
		return SUPPORTED_TYPES;
	}

}
