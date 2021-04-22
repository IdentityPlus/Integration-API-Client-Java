package identity.plus.api.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class HTTPS_Utils {
    
        /**
         * Generates a KeyStore object to be used with a TLS communication containing a list of trusted authorities. 
         * These authorities are issuers/signers of the certificate of the server we want to connect to, not the client certificates (credentials) we are connecting with.
         * This method is useful if we want to restrict the authority that can issue our server certificates, in case we use a self signed authority or an authority
         * that is not by default trusted by Java.
         * 
         * @param ca_data byte array representing the bytes from a PEM formated file containing a list of authorities. The bytes are presented as they are loaded from the file
         * 
         * @return a KeyStore object loaded and initialized with the authorities in the PEM file. 
         * While the object class is the same in both (keystore and truststore cases), this really is a trust
         * store and should be used to initialize the trust component of the security context.
         * @throws CertificateException 
         * @throws KeyStoreException 
         * @throws IOException 
         * @throws NoSuchAlgorithmException 
         * 
         * @throws Exception
         */
        public static KeyStore load_trusted_authorities(byte[] ca_data) throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException{
                if(ca_data == null) return null;
                
                CertificateFactory cert_factory = CertificateFactory.getInstance("X.509");
                Collection<? extends Certificate> ca_certificates = cert_factory.generateCertificates(new ByteArrayInputStream(ca_data));
                KeyStore trust_store = KeyStore.getInstance("JKS");
                trust_store.load(null);
                for(Certificate c : ca_certificates) trust_store.setCertificateEntry("trusted ca " + trust_store.size(), c);

                return trust_store;
        }

        /**
         * Generates a KeysStore object containing the client credentials (client certificate and private key) we use to authenticate 
         * ourselves to the server, and establish the mutually authenticated TLS connection. 
         * 
         * @param p12_data ca_data byte array representing the bytes from a PKCS12 formated file containing the certificate, private key and potentially authority chain. 
         * The bytes are presented as they are loaded from the file
         * @param p12_password .p12 files are usually password protected so this is the password to the file 
         * 
         * @return a KeyStore object initialized with the client credentials. This is a KeyStore and should be used to initialize the credentials (key) component of the security context
         * @throws IOException 
         * @throws CertificateException 
         * @throws NoSuchAlgorithmException 
         * @throws KeyStoreException 
         * 
         * @throws Exception
         */
        public static KeyStore load_credentials(byte[] p12_data, String p12_password) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException{
                if(p12_data == null) return null;

                KeyStore key_store = KeyStore.getInstance("JKS");
                key_store.load(new ByteArrayInputStream(p12_data), (p12_password ==  null ? "" : p12_password).toCharArray());

                return key_store;
        }


        /**
         * Generates a KeysStore object containing the client credentials (client certificate and private key) we use to authenticate 
         * ourselves to the server, and establish the mutually authenticated TLS connection. 
         * 
         * @param cert_data ca_data byte array representing the bytes from a PEM formated file containing the client certificate and potentially authority chain. 
         * The bytes are presented as they are loaded from the file
         * @param key_data byte array representing the private key component of the credential. It is also PEM formatted and bytes need to be presented as they are loaded from the file. 
         * 
         * @return a KeyStore object initialized with the client credentials. This is a KeyStore and should be used to initialize the credentials (key) component of the security context
         * @throws CertificateException 
         * @throws NoSuchAlgorithmException 
         * @throws KeyStoreException 
         * @throws IOException 
         * @throws InvalidKeySpecException 
         * 
         * @throws Exception
         */
        public static KeyStore load_credentials(byte[] cert_data, byte[] key_data) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, InvalidKeySpecException{
                if(cert_data == null) return null;

                CertificateFactory cert_factory = CertificateFactory.getInstance("X.509");
                Collection<? extends Certificate> certificates = cert_factory.generateCertificates(new ByteArrayInputStream(cert_data));
    
                String pem_key = new String(key_data, "UTF-8");
                int idx = pem_key.indexOf("-----BEGIN PRIVATE KEY-----");
                pem_key = pem_key.substring(idx + "-----BEGIN PRIVATE KEY-----".length(), pem_key.indexOf("-----END PRIVATE KEY-----", idx + "-----BEGIN PRIVATE KEY-----".length()));
                key_data = pem_key.getBytes();
                
                KeyFactory key_factory = KeyFactory.getInstance("RSA");
                PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(key_data));
                
                KeyStore key_store = KeyStore.getInstance("JKS");
                key_store.load(null);
                key_store.setKeyEntry("credentials", key_factory.generatePrivate(key_spec), new char[]{}, certificates.toArray(new Certificate[certificates.size()]));
                
                return key_store;
        }
   
        /**
         * Once we have the KeyStore and the TrustStore, we can generate the SSLContext to connect with. This context contains all the information to perform authenticated
         * TLS calls. 
         *  
         * @param credentials the KeyStore containing the credentials. If null, the context can be used to make unauthenticated calls.
         * @param keystore_pass the password is necessary if we loaded the credentials from a p12 format. Otherwise it can be null
         * @param trust_store the KeyStore object containing trust material. If null, the context can be used to connect to glabally accepted authorities
         * 
         * @return the initialized SSLContext. This object can be remembered as long as the credentials don't change and re-used
         * @throws NoSuchAlgorithmException 
         * @throws KeyStoreException 
         * @throws KeyManagementException 
         * @throws UnrecoverableKeyException 
         *  
         * @throws Exception
         */
        public static final SSLContext prepare_tls_context(KeyStore credentials, char[] keystore_pass, KeyStore trust_store) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException{
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                if(credentials != null) kmf.init(credentials, keystore_pass == null ? new char[]{} : keystore_pass);
                
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                if(trust_store != null) tmf.init(trust_store);
                
                SSLContext ctx = SSLContext.getInstance("TLSv1.2"); 
                ctx.init(credentials == null ? null : kmf.getKeyManagers(), trust_store == null ? null : tmf.getTrustManagers(), null);
                                
                return ctx;
        }
        
        
        /**
         * Makes an HTTP Call using no credentials
         * 
         * @param url the URL in the format https://domain/etc/etc
         * @param method the HTTP method (GET, POST, etc)
         * @param headers a list of headers formatted: {"Header-1-Name: value", ... , "Header-n-Name: value"}. Important, by default, no headers are passed, not even content type so it must be done by the caller
         * @param body the body of the HTTP call formatted according to the content type and transformed into bytes
         * @param ca_data trusted authorities file as explained in the load_trusted_authorities method. If it is null, the call defaults to generally trusted credentials
         * 
         * @return byte[] array containing the response body. If the response is anything but 200 OK, the code is affixed to the beginning of the response
         */
        public static final byte[] call(String url, String method, String[] headers, String body, byte[] ca_data){
            try{
                    KeyStore trusted_authorities = load_trusted_authorities(ca_data);
                    SSLContext tls_context = prepare_tls_context(null, null, trusted_authorities);
                    
                    return call(url, method, headers, body, tls_context);
            }
            catch(Exception e) {
                    return ("FAIL L4:" + e.getMessage()).getBytes();
            }
        }

        /**
         * Performs an https call using an authenticated TLS connection that is initialized using credentials stored in a PEM file
         * 
         * @param url the URL in the format https://domain/etc/etc
         * @param method the HTTP method (GET, POST, etc)
         * @param headers a list of headers formatted: {"Header-1-Name: value", ... , "Header-n-Name: value"}. Important, by default, no headers are passed, not even content type so it must be done by the caller
         * @param body the body of the HTTP call formatted according to the content type and transformed into bytes
         * @param p12_data ca_data byte array representing the bytes from a PKCS12 formated file containing the certificate, private key and potentially authority chain. 
         * The bytes are presented as they are loaded from the file
         * @param p12_pass the password is necessary if we loaded the credentials from a p12 format. Otherwise it can be null
         * @param ca_data byte array representing the bytes from a PEM formated file containing a list of authorities. The bytes are presented as they are loaded from the file
         * 
         * @return byte[] array containing the response body. If the response is anything but 200 OK, the code is affixed to the beginning of the response
         */
        public static final byte[] call(String url, String method, String[] headers, String body, byte[] p12_data, String p12_password, byte[] ca_data){
                try{
                        KeyStore credentials = load_credentials(p12_data, p12_password);
                        KeyStore trusted_authorities = load_trusted_authorities(ca_data);
                        SSLContext tls_context = prepare_tls_context(credentials, p12_password.toCharArray(), trusted_authorities);
                        
                        return call(url, method, headers, body, tls_context);
                }
                catch(Exception e) {
                    return ("FAIL L4:" + e.getMessage()).getBytes();
                }
        }
        
        /**
         * Performs an https call using an authenticated TLS connection that is initialized using a PEM encoded certificate / key pair
         * 
         * @param url the URL in the format https://domain/etc/etc
         * @param method the HTTP method (GET, POST, etc)
         * @param headers a list of headers formatted: {"Header-1-Name: value", ... , "Header-n-Name: value"}. Important, by default, no headers are passed, not even content type so it must be done by the caller
         * @param body the body of the HTTP call formatted according to the content type and transformed into bytes
         * @param cert_data ca_data byte array representing the bytes from a PEM formated file containing the client certificate and potentially authority chain. 
         * The bytes are presented as they are loaded from the file
         * @param key_data byte array representing the private key component of the credential. It is also PEM formatted and bytes need to be presented as they are loaded from the file. 
         * @param ca_data byte array representing the bytes from a PEM formated file containing a list of authorities. The bytes are presented as they are loaded from the file
         * 
         * @return byte[] array containing the response body. If the response is anything but 200 OK, the code is affixed to the beginning of the response
         */
        public static final byte[] call(String url, String method, String[] headers, String body, byte[] cert_data, byte[] key_data, byte[] ca_data){
                try{
                        KeyStore credentials = load_credentials(cert_data, key_data);
                        KeyStore trusted_authorities = load_trusted_authorities(ca_data);
                        SSLContext tls_context = prepare_tls_context(credentials, new char[]{}, trusted_authorities);
                        
                        return call(url, method, headers, body, tls_context);
                }
                catch(Exception e) {
                        return ("FAIL L4:" + e.getMessage()).getBytes();
                }
        }
                
        /**
         * Performs an https call using a predefined TLS context
         * 
         * @param url the URL in the format https://domain/etc/etc
         * @param method the HTTP method (GET, POST, etc)
         * @param headers a list of headers formatted: {"Header-1-Name: value", ... , "Header-n-Name: value"}. Important, by default, no headers are passed, not even content type so it must be done by the caller
         * @param body the body of the HTTP call formatted according to the content type and transformed into bytes
         * @param tls_context perfoms the call using a predefined TLS Context (credentials and trust is in the context)
         * 
         * @return byte[] array containing the response body. If the response is anything but 200 OK, the code is affixed to the beginning of the response
         */
        public static final byte[] call(String url, String method, String[] headers, String body, SSLContext tls_context){
                try {
                        URL endpoint = new URL(url);
                        HttpsURLConnection connection = (HttpsURLConnection)endpoint.openConnection();
                        connection.setSSLSocketFactory(tls_context.getSocketFactory());
                        
                        // set the method
                        connection.setRequestMethod(method.toUpperCase());
                        
                        // set the headers
                        if(headers != null) for(String header: headers) {
                                int idx = header.indexOf(":");
                                String name = header.substring(0, idx).trim();
                                String value = header.substring(idx +1).trim();
                                connection.addRequestProperty(name, value);
                        }
                        
                        connection.setDoOutput(true);
                        
                        if(body != null) {
                                OutputStreamWriter wr = new OutputStreamWriter(connection.getOutputStream());
                                wr.write(body);
                                wr.flush();
                        }
                        
                        int response_code = connection.getResponseCode();
        
                        byte[] data = drain(connection.getInputStream());
        
                        if(response_code != 200) return ("FAIL L7 " + response_code + ": " + new String(data, "UTF-8")).getBytes();
                        else return data;
                }
                catch(Exception e) {
                        e.printStackTrace();
                        return ("FAIL L5: " + e.getMessage()).getBytes();
                }
        }

        /**
         * Performs an https call using a predefined TLS context
         * 
         * @param url the URL in the format https://domain/etc/etc
         * @param method the HTTP method (GET, POST, etc)
         * @param headers a list of headers formatted: {"Header-1-Name: value", ... , "Header-n-Name: value"}. Important, by default, no headers are passed, not even content type so it must be done by the caller
         * @param body the body of the HTTP call formatted according to the content type and transformed into bytes
         * @param tls_context perfoms the call using a predefined TLS Context (credentials and trust is in the context)
         * 
         * @return byte[] array containing the response body. If the response is anything but 200 OK, the code is affixed to the beginning of the response
         */
        public static final void call(String url, String method, String[] headers, String body, SSLContext tls_context, HTTP_Response_Handler handler) throws IOException{
                URL endpoint = new URL(url);
                HttpsURLConnection connection = (HttpsURLConnection)endpoint.openConnection();
                connection.setSSLSocketFactory(tls_context.getSocketFactory());
                
                // set the method
                connection.setRequestMethod(method.toUpperCase());
                
                // set the headers
                if(headers != null) for(String header: headers) {
                        int idx = header.indexOf(":");
                        String name = header.substring(0, idx).trim();
                        String value = header.substring(idx +1).trim();
                        connection.addRequestProperty(name, value);
                }
                
                connection.setDoOutput(true);
                
                if(body != null) {
                        OutputStreamWriter wr = new OutputStreamWriter(connection.getOutputStream());
                        wr.write(body);
                        wr.flush();
                }
                
                handler.handle(connection.getResponseCode(), connection.getInputStream());
        }
        
        /**
         * Utility method to fully consume a stream (we use it to drain the HTTP Stream)
         * 
         * @param input_stream the Input Stream to consume
         * 
         * @return byte[] array of whatever was on the stream
         * 
         * @throws IOException
         */
        public static byte[] drain(InputStream input_stream) throws IOException{
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];

            int len = input_stream.read(buffer);

            while(len > 0){
                bos.write(buffer, 0, len);
                len = input_stream.read(buffer);
            }

            return bos.toByteArray();
        }
}
