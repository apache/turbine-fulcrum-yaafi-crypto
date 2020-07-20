package org.apache.fulcrum.jce.crypto;

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
 * Parameters for creating a password.
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl</a>
 */

public interface PasswordParameters
{
    /** Parameter for the number of SHA256 invocation */
    int COUNT = 1000;

    /** 
     * The default password used for creating the internal password 
     * @return the default password: <code>fulcrum-yaafi</code>.
     * */
    public static char[] DefaultPassword() { 
    	return new char[] {
        (char) 'f', (char) 'u', (char) 'l', (char) 'c',
        (char) 'r', (char) 'u', (char) 'm', (char) '-',
        (char) 'y', (char) 'a', (char) 'a', (char) 'f',
        (char) 'i'
        };
    }

    /** The password salt 
     * @return the 8bit default salt as byte array
     * */
    public static byte[] Salt() {
    	return new byte[] {
        (byte)0xc6, (byte)0x74, (byte)0x81, (byte)0x8a,
        (byte)0x7b, (byte)0xe8, (byte)0xfe, (byte)0x99
        };
    }
}
