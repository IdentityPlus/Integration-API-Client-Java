/*
 * (C) Copyright 2016 Identity+ (https://identity.plus) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This code is part of the identity+ API Wrapper suite and it is meant to facilitate
 * access to the identity + ReST Service. While the ReST service is not dependent 
 * upon this code, this code shortens implementation time because it wraps regular
 * ReST calls into a more developer friendly package.
 * 
 * You are free to make changes to this code to better suite your particular
 * implementation and keep it closed source, however, if you consider the changes are relevant to the
 * the identity + community, please consider donating your changes back to the community.
 * 
 * You are permitted to use the identity.plus package names in your fork as long as the 
 * code can be used exclusively to connect to the Identity + ReST API services.
 * 
 * Please submit bugs or improvement requests at https://identity.plus/
 *
 * Contributors:
 *         Stefan Harsan Farr
 */
package identity.plus.api;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;
/**
 * Some Utility functions
 * 
 * @author Stefan Harsan Farr
 */
public class Identity_Plus_Utils {
        /**
         * The Java implementation takes the JKS keystore type. (both JKS and PEM are exported).
         * this is the name under which the API client certificate is stored in the keystore 
         */
        public static final String API_CERT_ALIAS = "identity +";
        
        /**
         * We need to find this string in the identity + anonymous certificates. It is only  a secondary
         * verification in case multiple authorities are added to the trust store and thus multiple client certificates
         * can be presented
         */
        protected static final String ANONYMOUS_CLIENTS_TYPE = "Identity +  Anonymous Certificates";
        
        /**
         * Random number generator instance
         */
        private static Random RANDOM = new SecureRandom();
        
        /**
         * A pool of characters from which random sequences are created
         */
        private static final String RANDOM_LETTER_POOL = "ABCDEFGHJKLMNOPQRSTUVXYZabcdefghijkmnopqrstuvxyz";
        private static final String RANDOM_TEXT_POOL = "0123456789ABCDEFGHJKLMNOPQRSTUVXYZabcdefghijkmnopqrstuvxyz~!@#$%^&*()_+=[]{}<>?";
        private static final String RANDOM_NUM_POOL = "0123456789";
        
        /**
         * Extracts distinguished name from an X500Principal's name.
         *  
         * @param principal
         * @param field (can be CN, C, O, OU, ST, etc.)
         * @return
         */
        public static String extract_dn_field(X500Principal principal, String field){
                try{
                        for(Rdn rdn: new LdapName(principal.getName()).getRdns()){
                                if(rdn.getType().equalsIgnoreCase(field)) return rdn.getValue().toString();
                        }

                        return null;
                }
                catch(InvalidNameException e){
                        // this should not happen because the name has already been checked, coming from the X500Principal Object
                        throw new RuntimeException(e);
                }
        }

        public static byte[] section(byte[] src, int pos, int len){
                byte[] result = new byte[len];
                System.arraycopy(src, pos, result, 0, len);
                return result;
        }
        
        public static byte[] chain(byte[] ... byte_arrays){
                int len = 0;
                for(byte[] array : byte_arrays) len += array.length;
                byte[] ans = new byte[len];
                
                int pos = 0;
                for(byte[] array : byte_arrays){
                        System.arraycopy(array, 0, ans, pos, array.length);
                        pos += array.length;
                }
                
                return ans;
        }
        
        public static SecretKey random_symmetric_key() throws NoSuchAlgorithmException{
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                return keyGen.generateKey();
        }
        
        public static SecretKey bytes_to_key(byte[] encoded){
                return new SecretKeySpec(encoded, "AES");
        }

        public static byte[] encrypt(byte[] clear_text, SecretKey symmetric_key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
                byte[] iv = new byte[16]; RANDOM.nextBytes(iv);
                
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.ENCRYPT_MODE, symmetric_key, new IvParameterSpec(iv));
                
                byte[] encrypted_data = cipher.doFinal(clear_text);
                
                return chain(iv, encrypted_data);
        }
        
        public static byte[] decrypt(byte[] crypto_text, SecretKey symmetric_key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
                byte[] iv = section(crypto_text, 0, 16);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, symmetric_key, new IvParameterSpec(iv));
                
                byte[] decrypted_data = cipher.doFinal(section(crypto_text, 16, crypto_text.length -16));
                
                return decrypted_data;
        }

        public static byte[] hybrid_encrypt(byte[] clear_text, Key asymetric_key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
                SecretKey symmetric_key = random_symmetric_key();
                byte[] iv = new byte[16]; RANDOM.nextBytes(iv);
                
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.ENCRYPT_MODE, symmetric_key, new IvParameterSpec(iv));
                
                byte[] encrypted_data = cipher.doFinal(clear_text);
                byte[] symmetric_key_data = symmetric_key.getEncoded();
                byte[] key_data = encrypt(chain(symmetric_key_data, iv), asymetric_key);
                byte[] result = chain(new byte[]{(byte) ((key_data.length >> 24) & 0xFF), (byte) ((key_data.length >> 16) & 0xFF), (byte) ((key_data.length >> 8) & 0xFF), (byte) (key_data.length & 0xFF)}, key_data, encrypted_data);
                
                return result;
        }
        
        public static byte[] hybrid_decrypt(byte[] crypto_text, Key asymetric_key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
                int len = ((crypto_text[0] & 0xFF) << 24) | ((crypto_text[1] & 0xFF) << 16) | ((crypto_text[2] & 0xFF) << 8) | (crypto_text[3] & 0xFF);
                byte[] key_data = section(crypto_text, 4, len);
                byte[] decrypted_key_data = decrypt(key_data, asymetric_key);
                byte[] symmetric_key_data = section(decrypted_key_data, 0, 32);
                byte[] iv = section(decrypted_key_data, 32, 16);
                
                SecretKey symmetric_key = new SecretKeySpec(symmetric_key_data, "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, symmetric_key, new IvParameterSpec(iv));
                
                byte[] decrypted_data = cipher.doFinal(section(crypto_text, 4 + len, crypto_text.length -4 -len));
                
                return decrypted_data;
        }

        /**
         * Asymmetric encryption with a given key.
         * 
         * @param clear_text, the text to encrypt
         * @param asymetric_key, either the public or the private part of a PKI set
         * @return the encrypted text in bytes
         * 
         * @throws NoSuchAlgorithmException
         * @throws NoSuchPaddingException
         * @throws InvalidKeyException
         * @throws IllegalBlockSizeException
         * @throws BadPaddingException
         */
        public static byte[] encrypt(byte[] clear_text, Key asymetric_key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
                byte[] cipher_text = null;
                
                final Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, asymetric_key);
                cipher_text = cipher.doFinal(clear_text);
                
                return cipher_text;
        }
        
        /**
         * Asymmetric encryption with a given key.
         * 
         * @param cipher_text, encrypted text
         * @param opposite_asymetric_key, either the public or the private part of a PKI set, the opposite key to the encryption
         * @return if successful, the initial unencrypted text
         * 
         * @throws NoSuchAlgorithmException
         * @throws NoSuchPaddingException
         * @throws InvalidKeyException
         * @throws IllegalBlockSizeException
         * @throws BadPaddingException
         */
        public static byte[] decrypt(byte[] cipher_text, Key opposite_asymetric_key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
                byte[] clear_text = null;

                final Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, opposite_asymetric_key);
                clear_text = cipher.doFinal(cipher_text);

                return clear_text;
        }

        /**
         * Extracts the identity+ anonymous id from a certificate
         * 
         * @param cert
         * @return
         */
        public static String extract_identity_plus_anonymous_id(X509Certificate cert){
//                String organizational_unit = Identity_Plus_Utils.extract_dn_field(cert.getSubjectX500Principal(), "OU");
//                if(!ANONYMOUS_CLIENTS_TYPE.equals(organizational_unit)) return null;
        
                // if all passed, the common name is the anonymous id
                String common_name = Identity_Plus_Utils.extract_dn_field(cert.getSubjectX500Principal(), "CN");
                return common_name;
        }

        /**
         * Generates a random text of given length
         * 
         * @param length
         * @return
         */
        public static String random_text(int length){
                StringBuilder p = new StringBuilder();
                for(int i = 0; i < length; ++i) p.append(RANDOM_TEXT_POOL.charAt(RANDOM.nextInt(RANDOM_TEXT_POOL.length())));
                return p.toString();
        }

        /**
         * Generates a random text only from letters of given length
         * 
         * @param length
         * @return
         */
        public static String random_letters(int length){
                StringBuilder p = new StringBuilder();
                for(int i = 0; i < length; ++i) p.append(RANDOM_LETTER_POOL.charAt(RANDOM.nextInt(RANDOM_LETTER_POOL.length())));
                return p.toString();
        }

        /**
         * Generates a random numbers of given length
         * 
         * @param length
         * @return
         */
        public static String random_numbers(int length){
                StringBuilder p = new StringBuilder();
                for(int i = 0; i < length; ++i) p.append(RANDOM_NUM_POOL.charAt(RANDOM.nextInt(RANDOM_NUM_POOL.length())));
                return p.toString();
        }

        /**
         * gets the JSON Name from the Class, classes are named such that a simple conversion will fit the json objects 
         * exchanged with the API
         * 
         * @param classs
         * @return
         */
        public static String json_name(Class<?> classs){
                return classs.getName().substring(classs.getName().lastIndexOf('.') +1).replace('_', '-');
        }

        public static String client_IP_address(HttpServletRequest request) {  
                String ip = request.getHeader("X-Forwarded-For");  
                
                if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {  
                        ip = request.getHeader("Proxy-Client-IP");  
                }  
                
                if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {  
                        ip = request.getHeader("WL-Proxy-Client-IP");  
                }  
                
                if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {  
                        ip = request.getHeader("HTTP_CLIENT_IP");  
                }  
                
                if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {  
                        ip = request.getHeader("HTTP_X_FORWARDED_FOR");  
                }  
                
                if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {  
                        ip = request.getRemoteAddr();  
                }
                
                return ip;  
        }  

        public static byte[] compute_sha_512(byte[] data){
            try{
                    MessageDigest md = MessageDigest.getInstance("SHA-512");
                    byte[] hash = md.digest(data);
                    return hash;
            }
            catch(Exception e) {
                    throw new RuntimeException("Unable to compute 512 SHA", e);
            }
        }
}
