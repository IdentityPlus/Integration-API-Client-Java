/*
 * (C) Copyright 2016 Identity+ (https://identity.plus) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
 *     Stefan Harsan Farr
 */
package identity.plus.api;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.net.ssl.SSLContext;

import identity.plus.api.communication.API_Request;
import identity.plus.api.communication.API_Response;
import identity.plus.api.communication.Anonymous_ID;
import identity.plus.api.communication.Identity_Inquiry;
import identity.plus.api.communication.Identity_Profile;
import identity.plus.api.communication.Intent;
import identity.plus.api.communication.Intent_Reference;
import identity.plus.api.communication.Intrusion_Report;
import identity.plus.api.communication.Local_User_Information;
import identity.plus.api.communication.Local_User_Reference;
import identity.plus.api.communication.Message_Delivery_Request;
import identity.plus.api.communication.Message_Delivery_Response;
import identity.plus.api.communication.Personal_Data_Disclosure_Request;
import identity.plus.api.communication.Recovery_Code;
import identity.plus.api.communication.Redirect_Request;
import identity.plus.api.communication.Reference_Number;
import identity.plus.api.communication.Service_Agent_Identity;
import identity.plus.api.communication.Service_Agent_Identity_Request;
import identity.plus.api.communication.Service_Identity;
import identity.plus.api.communication.Service_Identity_Request;
import identity.plus.api.communication.Simple_Response;
import identity.plus.api.communication.Trust;
import identity.plus.api.communication.Unlock_Request;
import identity.plus.api.communication.User_Secret;
import identity.plus.api.util.HTTPS_Utils;

/**
 * Singleton Class responsible with conveying information from and to the server via the identity+ http api
 * This class should be instantiated once and used at each request. The Apache HTTP Client performs some 
 * connection caching so this may help with performance.
 * 
 * Methods are synchronized because they re-use the http_connection which should not be called simultaneously by 
 * more than one thread.
 * 
 * For heavy load sites, you could create more than one of these objects and pool them.
 *
 * @author Stefan Harsan Farr
 */
public class API_Channel {    
    /**
     * The parameter name when the response comes via redirect (legacy http identity+ only)
     */
    public static final String LEGACY_REDIRECT_RESPONSE_PARAMETER = "resp";
    public static final String NEW_REDIRECT_RESPONSE_PARAMETER = "identity-plus-intent";
    public static final String REGISTER_RESPONSE_PARAMETER = "identity-plus-register-intent";
    
    /**
     * Where to make the requests. The identity+ ReST API url 
     */
    public final String endpoint;
    
    /**
     * The private key of the API client certificate 
     */
    public final PrivateKey private_key;
    
    /**
     * the API client certificate
     */
    public final X509Certificate certificate;

    /**
     * SSLContext, we can re-use this
     */
    private final SSLContext tls_context;
    /**
     * Constructor
     * 
     * @param endpoint, same as field (Where to make the requests. The identity+ ReST API url )
     * @param key_store_location, the location of the keystore on the file system, if you need to load the keystore from a special place use the explicit constructor
     * @param key_store_pass, the keystore password. Unless you changed it, this is the password generated by identity + when the API certificate was issued
     * 
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws KeyManagementException
     * @throws UnrecoverableKeyException
     */
    public API_Channel(final String endpoint, String key_store_location, String key_store_pass) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyManagementException, UnrecoverableKeyException {
        this(endpoint, key_store_location, key_store_pass, null);
    }    
    /**
     * Constructor
     * 
     * @param endpoint, same as field (Where to make the requests. The identity+ ReST API url )
     * @param key_store_location, the location of the keystore on the file system, if you need to load the keystore from a special place use the explicit constructor
     * @param key_store_pass, the keystore password. Unless you changed it, this is the password generated by identity + when the API certificate was issued
     * @param trust_self_signed_certificates, forces the API to trust self signed server certificates. Use this for development purpose only!
     * 
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws KeyManagementException
     * @throws UnrecoverableKeyException
     */
    public API_Channel(String endpoint, String key_store_location, String key_store_pass, String trust_store_location) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyManagementException, UnrecoverableKeyException {

        KeyStore credentials = HTTPS_Utils.load_credentials(HTTPS_Utils.drain(new FileInputStream(key_store_location)), key_store_pass);
        KeyStore trusted_authorities = HTTPS_Utils.load_trusted_authorities(trust_store_location == null ? null : HTTPS_Utils.drain(new FileInputStream(trust_store_location)));
        
        this.endpoint = endpoint;
        this.certificate = (X509Certificate)credentials.getCertificate(Identity_Plus_Utils.API_CERT_ALIAS);
        private_key = (PrivateKey)credentials.getKey(Identity_Plus_Utils.API_CERT_ALIAS, key_store_pass.toCharArray());
        this.tls_context = HTTPS_Utils.prepare_tls_context(credentials, key_store_pass != null ? key_store_pass.toCharArray() : new char[]{}, trusted_authorities);
    }


    /**
     * Performs a get request for the Identity_Enquiry object
     * 
     * @param certificate_info
     * @return
     * @throws IOException
     */
    public synchronized API_Response get(Identity_Inquiry certificate_info) throws IOException{
        return dispatch(Request_Method.GET, certificate_info);
    }

    /**
     * Performs a get request for the Identity_Enquiry object
     * 
     * @param certificate_info
     * @return
     * @throws IOException
     */
    public synchronized API_Response ping() throws IOException{
        return dispatch(Request_Method.PUT, null);
    }

    /**
     * Performs a put request for the Local_User_Information object
     * 
     * @param local_user_information
     * @return
     * @throws IOException
     */
    public synchronized API_Response put(Local_User_Information local_user_information) throws IOException{
        return dispatch(Request_Method.PUT, local_user_information);
    }
    
    /**
     * Performs a put request for the Local_User_Information object
     * 
     * @param local_user_information
     * @return
     * @throws IOException
     */
    public synchronized API_Response put(Unlock_Request unlock_request) throws IOException{
        return dispatch(Request_Method.PUT, unlock_request);
    }

    /**
     * Performs a put request for the Intrusion_Report object
     * 
     * @param intrusion_report
     * @return
     * @throws IOException
     */
    public synchronized API_Response put(Intrusion_Report intrusion_report) throws IOException{
        return dispatch(Request_Method.PUT, intrusion_report);
    }

    /**
     * Performs a put request for the Intent request object
     * 
     * @since v2
     * @param intent
     * @return
     * @throws IOException
     */
    public synchronized API_Response put(Intent intent) throws IOException{
        return dispatch(Request_Method.PUT, intent);
    }

    /**
     * Performs a put request for the Trust object
     * 
     * @param local_user_update
     * @return
     * @throws IOException
     */
    public synchronized API_Response put(Trust local_user_update) throws IOException{
        return dispatch(Request_Method.PUT, local_user_update);
    }

    /**
     * Performs a put request for the Personal Data Disclosure object
     * 
     * @param local_user_update
     * @return
     * @throws IOException
     */
    public synchronized API_Response put(Personal_Data_Disclosure_Request pii_disclosure) throws IOException{
        return dispatch(Request_Method.PUT, pii_disclosure);
    }

    /**
     * Performs a put request for the Message Delivery Request
     * 
     * @param local_user_update
     * @return
     * @throws IOException
     */
    public synchronized API_Response put(Message_Delivery_Request mesage_delivery_request) throws IOException{
        return dispatch(Request_Method.PUT, mesage_delivery_request);
    }

    /**
     * Performs a put request for the User_Secret object
     * 
     * @param secret
     * @return
     * @throws IOException
     */
    public synchronized API_Response put(User_Secret secret) throws IOException{
        return dispatch(Request_Method.PUT, secret);
    }

    /**
     * Performs an HTTP Delete Request with the give Local_User_Reference
     * 
     * @param local_user_ref
     * @return
     * @throws IOException
     */
    public synchronized API_Response delete(Local_User_Reference local_user_ref) throws IOException{
        return dispatch(Request_Method.DELETE, local_user_ref);
    }
    
    /**
     * Makes the HTTP request to the default endpoint, given the method and the Java API Request_Object
     * 
     * @param method
     * @param api_request
     * @return
     * @throws IOException
     */
    private synchronized API_Response dispatch(final Request_Method method, API_Request api_request) throws IOException{
            return dispatch(endpoint, method, api_request);
    }
    
    
    /**
     * Makes the HTTP request to a given endpoint, given the method and the Java API Request_Object
     * 
     * @param endpoint. the url where the call will be made to
     * @param method
     * @param api_request
     * @return
     * @throws IOException
     */
    private synchronized API_Response dispatch(String endpoint, final Request_Method method, API_Request api_request) throws IOException{

        API_Response[] response = {null};
        
        HTTPS_Utils.call(endpoint, method.name(), new String[]{"Content-Type: application/json", "User-Agent: Identity + API Client"}, api_request != null ? api_request.to_json() : "", tls_context,  (int code, InputStream body) -> {
                JsonReader reader = Json.createReader(body);
                JsonObject jsso = reader.readObject();
                response[0] = decode_response(jsso);
        });
        
        return response[0];
    }
    
    /**
     * Extracts the raw JSON object from the HTTP response bytes
     * 
     * @param data
     * @return
     */
    public static API_Response decode_response(byte[] data){
        try{
            JsonReader reader = Json.createReader(new InputStreamReader(new ByteArrayInputStream(data), "UTF-8"));
            JsonObject jsso = reader.readObject();
            return decode_response(jsso);
        }
        catch(UnsupportedEncodingException e){
            // this should not happen as UTF-8 is suppoted
            throw new RuntimeException(e);
        }
    }
    
    /**
     * Parses the JSON objects into Java Classes
     * 
     * @param jsso
     * @return
     */
    public static API_Response decode_response(JsonObject jsso){
        if(jsso.keySet().contains(Identity_Profile.JSON_NAME)) return new Identity_Profile(jsso.getJsonObject(Identity_Profile.JSON_NAME));
        else if(jsso.keySet().contains(Anonymous_ID.JSON_NAME)) return new Anonymous_ID(jsso.getJsonObject(Anonymous_ID.JSON_NAME));
        else if(jsso.keySet().contains(Reference_Number.JSON_NAME)) return new Reference_Number(jsso.getJsonObject(Anonymous_ID.JSON_NAME));
        else if(jsso.keySet().contains(Intent_Reference.JSON_NAME)) return new Intent_Reference(jsso.getJsonObject(Intent_Reference.JSON_NAME));
        else if(jsso.keySet().contains(Message_Delivery_Response.JSON_NAME)) return new Intent_Reference(jsso.getJsonObject(Message_Delivery_Response.JSON_NAME));
        else if(jsso.keySet().contains(Service_Identity.JSON_NAME)) return new Service_Identity(jsso.getJsonObject(Service_Identity.JSON_NAME));
        else if(jsso.keySet().contains(Service_Agent_Identity.JSON_NAME)) return new Service_Agent_Identity(jsso.getJsonObject(Service_Agent_Identity.JSON_NAME));
        else if(jsso.keySet().contains(Recovery_Code.JSON_NAME)) return new Recovery_Code(jsso.getJsonObject(Recovery_Code.JSON_NAME));
        else return new Simple_Response(jsso.getJsonObject(Simple_Response.JSON_NAME));
    }
    
    /**
     * Computes the anonymous id call based on a return url. It encrypts the request with the API certificate private key 
     * and formats the URL.
     *  
     * @param return_url, upon retrival, the identity+ API will redirect the browser back to this URL with information stored in the query
     * @return the point where to redirect client browser for anonymous id retrival (legacy HTTP)
     */
    public String anonymous_id_retrival_endpoint(String return_url){
        try{
            Redirect_Request extraction = new Redirect_Request(return_url);
            byte[] retrival_bytes = extraction.to_json().getBytes("UTF-8");
            if(retrival_bytes.length > 245) throw new RuntimeException("Return URL is too long. Instead of adding a long query, you can store the query in session variable and append pass the variable's id to the request.");
            
            StringBuilder sb = new StringBuilder(endpoint + "/anonymous-id?api=");
            sb.append(certificate.getSerialNumber());
            sb.append("&payload=");
            sb.append(Base64.getUrlEncoder().encodeToString(Identity_Plus_Utils.encrypt(retrival_bytes, private_key)));
            
            return sb.toString();
        }
        catch(UnsupportedEncodingException e){
            // should not happen UTF-8 is supported
            throw new RuntimeException(e);
        }
        catch(InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e){
            // normally this should not happen if the key is good
            throw new RuntimeException(e);
        }
    }

    /**
     * Computes the certificate validation endpoint, based on a return URL. It encrypts the request with the API certificate private key
     * and formats the URL.
     * In case the certificate is invalid or needs user attention this is the point where to redirect the client browser.
     * 
     * @param return_url, upon validation, the identity+ API will redirect the browser back to this URL with information stored in the query
     * @return the point where to redirect client browser for certificate problem resolutions
     */
    public String certificate_validation_endpoint(String return_url){
        try{
            Redirect_Request extraction = new Redirect_Request(return_url);
            byte[] retrival_bytes = extraction.to_json().getBytes("UTF-8");
            if(retrival_bytes.length > 245) throw new RuntimeException("Return URL is too long. Instead of adding a long query, you can store the query in session variable and append pass the variable's id to the request.");
            
            String endpoint = this.endpoint.replace("api.", "signon.");
            endpoint = endpoint.substring(0,  endpoint.lastIndexOf('/'));
            
            StringBuilder sb = new StringBuilder(endpoint + "?api=");
            sb.append(certificate.getSerialNumber());
            sb.append("&payload=");
            sb.append(Base64.getUrlEncoder().encodeToString(Identity_Plus_Utils.encrypt(retrival_bytes, private_key)));
            
            return sb.toString();
        }
        catch(UnsupportedEncodingException e){
            // should not happen UTF-8 is supported
            throw new RuntimeException(e);
        }
        catch(InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e){
            // normally this should not happen if the key is good
            throw new RuntimeException(e);
        }
    }
    
    public String intent_endpoint(Intent_Reference intent){
        String ep = endpoint.replaceAll("api", "signon") ;
        ep = ep.substring(0,  ep.lastIndexOf('/'));
        
        return ep + "/" + intent.value;
    }

    public String intent_endpoint(Intent_Reference intent, String path){
        String ep = endpoint.replaceAll("api", "signon") ;
        ep = ep.substring(0,  ep.lastIndexOf('/'));
        
        if(path.length() > 0) path = path + "/";
        
        return ep + "/" + path + intent.value;
    }

    public API_Response issue_service_identity(boolean force) throws IOException{
            return issue_service_identity(null, force);
    }
    
    public API_Response issue_service_identity(String service_domain, boolean force) throws IOException{
        API_Response response = dispatch(Request_Method.PUT, new Service_Identity_Request(service_domain, force));
        return response;
    }

    public API_Response issue_service_agent_identity(String agent_name) throws IOException{
        return issue_service_agent_identity(null, agent_name);
    }
    
    public API_Response issue_service_agent_identity(String service_domain, String agent_name) throws IOException{
        API_Response response = dispatch(Request_Method.PUT, new Service_Agent_Identity_Request(service_domain, agent_name));
        return response;
    }

    public API_Response issue_service_agent_identity(String intent_id, String service_domain, String agent_name) throws IOException{
        API_Response response = dispatch(certificate_validation_endpoint(""), Request_Method.PUT, new Service_Agent_Identity_Request(service_domain, agent_name));
        return response;
    }
}
