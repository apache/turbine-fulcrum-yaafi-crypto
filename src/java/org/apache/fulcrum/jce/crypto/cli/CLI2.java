package org.apache.fulcrum.jce.crypto.cli;

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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.fulcrum.jce.crypto.HexConverter;
import org.apache.fulcrum.jce.crypto.StreamUtil;
import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8;
import org.apache.fulcrum.jce.crypto.extended.CryptoParametersJ8.TYPES;
import org.apache.fulcrum.jce.crypto.extended.CryptoUtilJ8;

/**
 * Command line tool for encrypting/decrypting a file or string
 *
 * file [enc|dec] passwd [file]*
 * string [enc|dec] passwd plaintext
 * 
 * Example :
 * 
 * java -classpath target/classes org.apache.fulcrum.jce.crypto.cli.CLI2 string enc changeit mysecretgeheim
 * ...
 * 
 * java -cp target/classes org.apache.fulcrum.jce.crypto.cli.Main string dec changeit J8_AES256;<hashcode>
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl</a>
 */

public class CLI2
{
    /**
     * Allows usage on the command line.
     * 
     * @param args the command line parameters
     */
    public static void main( String[] args )
    {
        try
        {

            if (args.length ==0 ){
                printHelp();
                return;
            }
            String operationMode = args[0];
            
            String msg = "No operationMode" ;
            if (operationMode == null || operationMode.equals("")) 
            {
                throw new IllegalArgumentException(msg);
            }
            
            if( operationMode.equals("info") )
            {
                printInfo();
                return;
            } 
            else if (operationMode.equals("help") ) 
            {
                printHelp();
                return;
            }
            
            if( args.length < 3 )
            {
                printHelp();
                throw new IllegalArgumentException("Invalid command line");
            }


            if( operationMode.equals("file") )
            {
                processFiles(args);
            }
            else if( operationMode.equals("string") )
            {
                processString(args);
            }
        }
        catch (Exception e)
        {
            System.out.println("Error : " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void printInfo() 
    {
        CryptoUtilJ8 cryptoUtilJ8 = CryptoUtilJ8.getInstance();
        System.out.println("\tCrypto factory class: " + cryptoUtilJ8.getCryptoStreamFactory().getClass());
        System.out.println("\tDefault Algorithm used: " + cryptoUtilJ8.getCryptoStreamFactory().getAlgorithm());
        String algoShortList= Arrays.stream(CryptoParametersJ8.TYPES.values()).map(t-> t.toString()).collect(Collectors.joining(","));
        System.out.println("\tAlgorithms (shortcut) available: " + algoShortList);
        String algoList= Arrays.stream(CryptoParametersJ8.TYPES_IMPL.values()).map(t-> t.toString()).collect(Collectors.joining(", "));
        System.out.println("\tAlgorithms available: " + algoList);
        System.out.println("\tMore Info: https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html");
    }

    /**
     * Prints usage information.
     */
    public static void printHelp()
    {
        System.out.println("\r\n\t*** Command line tool for encrypting/decrypting strings/files ***\r\n\t*** algorithm based on "+ CryptoParametersJ8.TYPES_IMPL.ALGORITHM_J8_PBE+ "***\r\n");
        System.out.println("\tjava -cp target\\classes; "+ CLI2.class.getName()+ " <operation mode> <coding mode> <password> <path|string> [target]\r\n");
        System.out.println("\t\toperation mode: file|string|info");
        System.out.println("\t\tcoding mode: enc|dec|enc:GCM. Default algorithm is " + TYPES.PBE);
        System.out.println("\t\t<password: string or empty:''");
        System.out.println("\t\tcode|coderef: path|string");
        System.out.println("\t\ttarget: optional\r\n");
        System.out.println( "\t*** Usage: ***\r\n");
        System.out.println("\t\t"+ CLI2.class.getSimpleName()+ " file [enc|dec] passwd source [target]");
        System.out.println("\t\t"+ CLI2.class.getSimpleName() + " string [enc|dec] passwd source");
        System.out.println("\t\t"+ CLI2.class.getSimpleName() + " info");
    }

    /**
     * Decrypt/encrypt a list of files
     * @param args the command line
     * @throws Exception the operation failed
     */
    public static void processFiles(String[] args)
        throws Exception
    {
        String cipherMode = args[1];
        char[] password = args[2].toCharArray();
        File sourceFile = new File(args[3]);
        File targetFile = null;

        if (args.length == 4)
        {
            targetFile = sourceFile;
        }
        else
        {
            targetFile = new File(args[4]);
            File parentFile = targetFile.getParentFile(); 

            if (parentFile != null && (!parentFile.exists() || !parentFile.isDirectory()))
            {
                boolean success = parentFile.mkdirs();
                if ( !success )
                {
                	System.err.println("Error, could not create directory to write parent file");
                }            	
            }
        }

        processFile(cipherMode,password,sourceFile,targetFile);
    }

    /**
     * Decrypt/encrypt a single file
     * @param cipherMode the mode
     * @param password the password
     * @param sourceFile the file to process
     * @param targetFile the target file
     * @throws Exception the operation failed
     */
    public static void processFile(String cipherMode, char[] password, File sourceFile, File targetFile)
        throws Exception
    {
                
        try (FileInputStream fis = new FileInputStream(sourceFile)) 
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CryptoUtilJ8 cryptoUtilJ8 = createCryptoUtil(cipherMode);
    
            if( cipherMode.startsWith("dec") )
            {
                System.out.println("Decrypting " + sourceFile.getAbsolutePath() );
            
                //String value = new String(Files.readAllBytes(Paths.get(sourceFile.toURI())));
                StringBuffer stringBuffer = new StringBuffer();
                int i; 
                while ((i=fis.read()) != -1)  
                {
                    stringBuffer.append((char) i); 
                } 
                
                String value = stringBuffer.toString();
                if (isHexadecimal(value)) 
                {
                    byte[] buffer = HexConverter.toBytes(value);
                    cryptoUtilJ8.decrypt( buffer, baos, password );
                } 
                else 
                {
                    try ( FileInputStream fis2 = new FileInputStream(sourceFile) ) 
                    {
                        cryptoUtilJ8.decrypt( fis2, baos, password );
                    }
                }
    
                ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
                FileOutputStream fos = new FileOutputStream(targetFile);
                StreamUtil.copy(bais,fos);
                bais.close();
                fos.close();
            }
            else if( cipherMode.startsWith("enc") )
            {
                System.out.println("Encrypting " + sourceFile.getAbsolutePath() );
                cryptoUtilJ8.encrypt( fis, baos, password );
                fis.close();
    
                ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
                FileOutputStream fos = new FileOutputStream(targetFile);
                StreamUtil.copy(bais,fos);
                bais.close();
                fos.close();
            }
            else
            {
                String msg = "Don't know what to do with : " + cipherMode;
                throw new IllegalArgumentException(msg);
            }
        }
    }

    private static CryptoUtilJ8 createCryptoUtil(String cipherMode) throws Exception 
    {
        CryptoUtilJ8 cryptoUtilJ8 = null;
        if (cipherMode.endsWith(TYPES.PBE.toString()) || cipherMode.substring("enc".length()).equals("") ) 
        {
            cryptoUtilJ8 = CryptoUtilJ8.getInstance();
        } 
        else 
        {
            Optional<TYPES> algoShortcut = Arrays.stream(CryptoParametersJ8.TYPES.values()).filter(a-> cipherMode.endsWith(a.toString())).findFirst(); //.collect(Collectors.toList());
            if (algoShortcut.isPresent()) 
            {
                cryptoUtilJ8 = CryptoUtilJ8.getInstance(algoShortcut.get());
            }
        }
        
        if (cryptoUtilJ8 == null) 
        {
            throw new Exception("Could not find any algorithms. check provided alog shortcuts with CLI2 info!");
        }
        
        return cryptoUtilJ8;
    }

    /**
     * Decrypt and encrypt a string.
     * 
     * @param args the command line
     * @throws Exception the operation failed
     */
    public static void processString(String[] args)
        throws Exception
    {
        String cipherMode = args[1];
        char[] password = args[2].toCharArray();
        String value = args[3];
        File targetFile = null;
        
        if (args.length == 5) 
        {
            targetFile = new File(args[4]);
            File parentFile = targetFile.getParentFile(); 

            if (parentFile != null && (!parentFile.exists() || !parentFile.isDirectory()))
            {
                boolean success = parentFile.mkdirs();
                if ( !success )
                {
                  System.err.println("Error, could not create directory to write parent file");
                }
                
            }
        }
        
        if (value != null && !value.equals("")) 
        {
        
            String result = processString(cipherMode, password, value);
            
            if (targetFile != null) {
       
              try (OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(targetFile), Charset.forName("UTF-8").newEncoder() ) )
              {
                osw.write(result);
              }
            } else {
               System.out.println( result );
            }
        }
    }
    
    /**
     * Decrypt and encrypt a string.
     * 
     * @param cipherMode \"dec|enc\" + @link{TYPES}
     * @param password as char array
     * @param value String to be en/decrypted
     * @throws Exception the operation failed
     */
    public static String processString(String cipherMode, char[] password, String value)
        throws Exception
    {  
        if (value != null && !value.equals("")) 
        {
            CryptoUtilJ8 cryptoUtilJ8 = createCryptoUtil(cipherMode);
    
            String result = null;
            if ( cipherMode.startsWith("dec") )
            {
                result = cryptoUtilJ8.decryptString(value,password);
            }
            else if ( cipherMode.startsWith("enc"))
            {
                result = cryptoUtilJ8.encryptString(value,password);
            }
            return result;
        } else {
          return null;
        }
    }
    
    private static final Pattern HEXADECIMAL_PATTERN = Pattern.compile("\\p{XDigit}+");

    public static boolean isHexadecimal(String input) {
        final Matcher matcher = HEXADECIMAL_PATTERN.matcher(input);
        return matcher.matches();
    }
}