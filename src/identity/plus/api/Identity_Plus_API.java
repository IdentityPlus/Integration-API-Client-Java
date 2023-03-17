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

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.json.Json;
import javax.json.JsonReader;
import javax.servlet.http.HttpServletRequest;

import identity.plus.api.communication.API_Response;
import identity.plus.api.communication.Anonymous_ID;
import identity.plus.api.communication.Identity_Inquiry;
import identity.plus.api.communication.Identity_Profile;
import identity.plus.api.communication.Intent;
import identity.plus.api.communication.Intent_Type;
import identity.plus.api.communication.Intrusion_Report;
import identity.plus.api.communication.Local_User_Information;
import identity.plus.api.communication.Local_User_Reference;
import identity.plus.api.communication.Message_Delivery_Request;
import identity.plus.api.communication.Outcome;
import identity.plus.api.communication.Personal_Data_Disclosure_Request;
import identity.plus.api.communication.Trust;
import identity.plus.api.communication.Unlock_Request;
import identity.plus.api.communication.User_Secret;
/**
 * The Identity + API wrapper.
 * 
 * This class needs to be created for each request, ideally as the first thing in each JSP, or servlet.
 * It has all the necessary operations for the functioning of the API. Please read in-line comments 
 * for further details.
 * 
 * @author Stefan Harsan Farr
 */
public class Identity_Plus_API {
    /**
     * just a key to store the Identity + Profile id in the session, so that we don't have to make the call at each request
     */
    public static final String SERIAL_NO_SESSION_KEY = "identity.plus.serial-no"; 
    
    /**
     * the servlet request, we pass through constructor
     */
    protected final HttpServletRequest http_request;
    
    /**
     * the api channel we pass through constructor, since the api channel need not be created at each request
     */
    protected final API_Channel api_channel;
    
    /**
     * The extracted api certificate, it will be extracted, if possible, during construction
     */
    private X509Certificate certificate;
    
    /**
     * The anonymous id from the certificate, if extracted
     */
    private String serial_number;
    
    /**
     * The identity profile, either from cache or freshly received via the API
     */
    private Identity_Profile identity_profile;
    
    /**
     * The outcome of the request made by the API 
     */
    private Outcome outcome;
    
    /**
     * Flag to force skipping legacy call. By default, if the API fails to extract the certificate the mainstream (HTTPS) way
     * it will automatically try to do it via the legacy HTTP redirect
     */
    public final boolean skip_legacy_call;

    /**
     * Holds the name of the device the client is connecting with.
     * This is only informative information, should not be considered a security tool, 
     * it is not unique among users
     */
    public String device_id;

    /**
     * Constructor, It constructs an API Channel
     * 
     * Please see field descriptions and in-line comments for details
     * 
     * @param api_channel
     * @param request
     * @param skip_legacy_call
     */
    public Identity_Plus_API(API_Channel api_channel, HttpServletRequest request, boolean skip_legacy_call){
        this.http_request = request;
        this.api_channel = api_channel;
        this.skip_legacy_call = skip_legacy_call & request.isSecure();

        // extract the key from the presented certificate chain
        // do this every time, the user may come with a different device or somebody
        // may have hijacked the session
        if(request.isSecure()) get_id_from_certificate();

        // request was detected as secure but there is a reverse proxy in between
        if(serial_number == null){
                serial_number = request.getHeader("X-TLS-Client-Serial");
                if(serial_number == null || serial_number.length() == 0)  log(3, "This is not a secure (SSL/TLS) connection. If you offloading TLS on a reverse proxy, please forward the client certificate serial number in the X-TLS-Client-Serial header", null);
                else serial_number =  new BigInteger(serial_number, 16).toString();
        }
        
        if("".equals(serial_number)) serial_number = null;
        
        if(serial_number == null){
            // certificate not found, this means we either don't have SSL or the 
            // server does not recognize the Identity + certificate or the browser
            // or the client simply does not have a certificate
            outcome = Outcome.PB_0000_No_Identity_Plus_anonymous_certificate;
            
            if(!skip_legacy_call){
                // try it the legacy way if not disabled
                // if we find it in the session, get it from there
                serial_number = get_session_variable(SERIAL_NO_SESSION_KEY);

                // will go the legacy way only if this is a legacy redirect callback
                if(serial_number == null && is_legacy_call()){
                        serial_number = get_legacy_response_reference(); // get_id_from_legacy_response();
                        if(serial_number != null) {
                                set_session_variable(SERIAL_NO_SESSION_KEY, serial_number);
                        }
                }
            }
        }
        
        // else will not work, in the upper if, the serial number might obtain a value
        if(serial_number != null){
            // found the anonymous id
            // found the id, this means we can do device authentication
            String cached_profile = get_session_variable(SERIAL_NO_SESSION_KEY + "/profile");
            
            if(cached_profile != null) {
                JsonReader json_reader = Json.createReader(new StringReader(cached_profile));
                this.identity_profile = new Identity_Profile(json_reader.readObject().getJsonObject("Identity-Profile"));
                outcome = this.identity_profile.outcome;
            }
            else try {
                // the validation has not yet been done, let's do that
                API_Response idp_response = api_channel.get(new Identity_Inquiry(serial_number, null, Identity_Plus_Utils.client_IP_address(request)));
                update_cached_profile(idp_response);
                outcome = this.identity_profile.outcome;
            }
            catch(IOException e){
                this.outcome = Outcome.ER_1106_General_Identity_Plus_API_Problem;
                log(0, "Cannot make api call", e);
            }
        }
    }
    
    /**
     * We update the cached profile. In case of subsequent calls such as adding trust or secret
     * the API will return an updated profile. We need to re-cache that
     * 
     * @param idp_response
     */
    private void update_cached_profile(API_Response idp_response){
        this.outcome = idp_response.outcome;

        if(idp_response instanceof Identity_Profile){
            // we have an identity status that is normal,
            // bind it to the session so that we don't have to issue another request on this session

            this.identity_profile = (Identity_Profile)idp_response;
            set_session_variable(SERIAL_NO_SESSION_KEY + "/profile", this.identity_profile.to_json());
        }
    }

    /**
     * Clear the cached profile. In case of log out
     * we need to do this
     * 
     * @param idp_response
     */
    public void clear(){
        set_session_variable(SERIAL_NO_SESSION_KEY, null);
        set_session_variable(SERIAL_NO_SESSION_KEY + "/profile", null);
        identity_profile = null;
    }

    /**
     * Clear the cached profile. In case of log out
     * we need to do this
     * 
     * @param idp_response
     */
    public void clear_cached_profile(){
        set_session_variable(SERIAL_NO_SESSION_KEY + "/profile", null);
        identity_profile = null;
    }
    
    /**
     * Gets the outcome
     * @return Outcome
     */
    public Outcome get_outcome(){
        return outcome;
    }
    
    /**
     * gets the certificate if any
     * @return, null if certificate could not be extracted 
     */
    public X509Certificate get_client_certificate(){
        return certificate;
    }
    
    /**
     * gets the anonymous id if any
     * @return, null if certificate, and consequently the anonymous id, could not be extracted 
     */
    public String get_anonymous_id(){
        return serial_number;
    }
    
    /**
     * @return the Identity_Profile or null if not available yet
     */
    public Identity_Profile get_identity_profile(){
        return identity_profile;
    }

    /**
     * verifies the request to determine if it is a return call from legacy http id extraction
     * @return
     */
    public boolean is_legacy_call(){
        return http_request.getMethod().equals("GET") && http_request.getParameter(API_Channel.NEW_REDIRECT_RESPONSE_PARAMETER) != null;
    }
    
    /**
     * gets the anonymoys id from the legacy response get request parameter
     */
    @Deprecated
    protected void get_id_from_legacy_response(){
        // we do not have SSL so we check if we receive the anonymous id via redirect
        try{
            byte[] response_data = Base64.getUrlDecoder().decode(http_request.getParameter(API_Channel.LEGACY_REDIRECT_RESPONSE_PARAMETER));

            // we need to decrypt it with our private key because this data is encrypted with our public key,
            // which in this particular case is not so public, but rather only known by the Identity + service
            byte[] decrypted_response = Identity_Plus_Utils.decrypt(response_data, api_channel.private_key);
            
            API_Response resp = API_Channel.decode_response(decrypted_response);

            this.outcome = resp.outcome;

            if(resp instanceof Anonymous_ID){
                serial_number = ((Anonymous_ID)resp).serial_number;

                // this means we got the ID the legacy http way with a redirect,
                // to make sure no redirections happen at each request, let's cache it in the session
                set_session_variable(SERIAL_NO_SESSION_KEY, serial_number);
                
                // let's verify if session stores it
                if(get_session_variable(SERIAL_NO_SESSION_KEY) == null || !get_session_variable(SERIAL_NO_SESSION_KEY).equals(serial_number)){
                        outcome = Outcome.ER_1106_General_Identity_Plus_API_Problem;
                        log(0, "When using the http legacy way you must allow the id to be stored in the session to avoid redirects at each request of the user.", null);
                }
            }
        }
        catch(InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e){
                // this is bad, it means the response is not coming from Identity + or it has been tempered with
                this.outcome = Outcome.PB_0007_Crypto_Failure_package_was_tempered_with;
                log(3, "Failed reading anonymous id from legacy response...", e);
        }
    }

    /**
     * gets the anonymoys id from the legacy response get request parameter
     */
    protected String get_legacy_response_reference(){
        return http_request.getParameter(API_Channel.NEW_REDIRECT_RESPONSE_PARAMETER);
    }
    
    /**
     * Attempts to extract the anonymous id from the certificate
     */
    protected void get_id_from_certificate(){
        X509Certificate cert_chain[] = (X509Certificate[]) http_request.getAttribute("javax.servlet.request.X509Certificate");
        if(cert_chain != null && cert_chain.length > 0){
                this.certificate = cert_chain[0];
                this.serial_number = certificate.getSerialNumber().toString();
                this.device_id = Identity_Plus_Utils.extract_dn_field(certificate.getSubjectX500Principal(), "CN");
                return;
        }
        // we should not get here if there is a certificate
        else if(cert_chain != null) for(X509Certificate cert : cert_chain){
                String  anonymous_id = Identity_Plus_Utils.extract_identity_plus_anonymous_id(cert);
                System.out.println("Identifying with: " + anonymous_id);
                
                if(anonymous_id != null){
                        this.certificate = cert;
                        this.serial_number = anonymous_id;
                        return;
                }
                else log(5, "Unknown certificate: " + cert.getSubjectX500Principal(), null);
        }
        else log(3, "Unable to read client certificate...", null);
    }

    /**
     * logs the message, by default to the standard output.
     * Override this method to redirect logging
     * 
     * @param verbosity_level
     * @param message
     * @param exception
     */
    protected void log(int verbosity_level, String message, Throwable exception){
        System.out.println(verbosity_level + ": " + message);
        if(exception != null) exception.printStackTrace();
    }
    
    /**
     * Default implementation for the session attribute recovery
     * override this method to store session attributes in a non standard way
     */
    protected String get_session_variable(String key) {
        return (String)http_request.getSession(true).getAttribute(key);
    }
    
    /**
     * Default implementation for the session attribute storing
     * override this method to store session attributes in a non standard way
     */
    protected void set_session_variable(String key, String value) {
       if(value == null) http_request.getSession().removeAttribute(key); 
       else http_request.getSession(true).setAttribute(key, value);
    }

   /**
    * Computes the URL address for returning to a give url relative to the root context. "/" needs to be added
    * this is a convenience method
    * 
    * @param relative_url, a page like /profile
    * @return
    */
   public String return_to(String relative_url){
        StringBuilder original_url = new StringBuilder(http_request.getScheme());
        original_url.append("://");
        original_url.append(http_request.getServerName());
        if(http_request.getServerPort() != 80 && http_request.getServerPort() != 443){
            original_url.append(':');
            original_url.append(http_request.getServerPort());
        }

        original_url.append(relative_url);
        
        return original_url.toString();
   }
   
   /**
    * Computes the URL address for returning to the same place, it is useful when making legacy calls or 
    * certificate validation redirects.
    * 
    * @return
    */
   public String return_here(){
        String url = ((String)http_request.getAttribute("javax.servlet.forward.request_uri"));
        if(url == null) url = http_request.getRequestURI();
        
        StringBuilder original_url = new StringBuilder(http_request.getScheme());
        original_url.append("://");
        original_url.append(http_request.getServerName());
        if(http_request.getServerPort() != 80 && http_request.getServerPort() != 443){
            original_url.append(':');
            original_url.append(http_request.getServerPort());
        }
        original_url.append(url);
        
        String query = http_request.getQueryString();
        if(query != null && query.length() > 0){
            // strip away idp api response if there is one
            int idx = query.indexOf(API_Channel.NEW_REDIRECT_RESPONSE_PARAMETER); 
            if(idx >= 0){
                int end = query.indexOf("&", idx);
                query = query.substring(0, idx) + (end >= 0 ? query.substring(end) : "");
            }

            // check again just in case we stripped
            if(query.length() > 0){
                original_url.append("?");
                original_url.append(query);
            }
        }
        
        return original_url.toString();
    }
    
   /**
    * Creates and submits an intrusion report from the given data and the data extracted from the request
    * 
    * @param severity, intrusion severity
    * @param message, message to send to the user
    * @param additional_information, additional information if any
    * @throws IOException
    */
    public void report_intrusion(Object_Of_Intrusion severity, String message, String additional_information) throws IOException{
        ArrayList<String> request_headers = new ArrayList<String>();
        for(Enumeration<String> header_names = http_request.getHeaderNames(); header_names.hasMoreElements(); ){
            String header = header_names.nextElement();
            request_headers.add(header + " = " + http_request.getHeader(header));
        }
        
        API_Response response = api_channel.put(new Intrusion_Report(
                                serial_number, 
                                severity, 
                                message, 
                                http_request.getLocalAddr(), 
                                http_request.getRequestURI(), 
                                request_headers, 
                                additional_information)
                        );

        update_cached_profile(response);
    }
    
    /**
     * Connects identity to local user. Formats and submits the request via the channel
     * Formats the request, calls it via the api channel and updates the cached user profile
     * 
     * @param local_user_uid, local unique user reference (id)
     * @param account_age_in_days, how long is this account with your service, in days
     * @param tokes_of_trust_as_of_yet, tokens of trust you want to award this user. 10 will be added by default
     * @throws IOException
     */
    public void connect_with_user(String local_user_uid, int account_age_in_days, int tokes_of_trust_as_of_yet) throws IOException{
        tokes_of_trust_as_of_yet = Math.min(tokes_of_trust_as_of_yet, 2500); // do not put more than 2500 points, the max amount that can be gathered on one site is 10000
        tokes_of_trust_as_of_yet = Math.max(10, tokes_of_trust_as_of_yet); // do not put less than 10 point. Being a user means trust
        API_Response response = api_channel.put(new Local_User_Information(
                                    null,
                                    serial_number,
                                    local_user_uid, 
                                    new BigInteger(String.valueOf(account_age_in_days)), 
                                    new BigInteger(String.valueOf(tokes_of_trust_as_of_yet))
                        ));

        update_cached_profile(response);
    }

    /**
     * Creates an identity plus identity and connect it to local user. Formats and submits the request via the channel
     * Formats the request, calls it via the api channel and updates the cached user profile
     * 
     * @param local_user_uid, local unique user reference (id)
     * @param account_age_in_days, how long is this account with your service, in days
     * @param tokes_of_trust_as_of_yet, tokens of trust you want to award this user. 10 will be added by default
     * @throws IOException
     */
    public void register_user(String local_user_uid, int account_age_in_days, int tokes_of_trust_as_of_yet) throws IOException{
        tokes_of_trust_as_of_yet = Math.min(tokes_of_trust_as_of_yet, 2500); // do not put more than 2500 points, the max amount that can be gathered on one site is 10000
        tokes_of_trust_as_of_yet = Math.max(10, tokes_of_trust_as_of_yet); // do not put less than 10 point. Being a user means trust
        API_Response response = api_channel.put(new Local_User_Information(
                                    null,
                                    "+",
                                    local_user_uid, 
                                    new BigInteger(String.valueOf(account_age_in_days)), 
                                    new BigInteger(String.valueOf(tokes_of_trust_as_of_yet))
                        ));

        update_cached_profile(response);
    }
    
    public void put_trust() throws IOException{
        put_trust(Object_Of_Trust.random);
    }

    /**
     * Change the user secret. Please refer to best practices with this
     * Formats the request, calls it via the api channel and updates the cached user profile
     * 
     * @param secret
     * @throws IOException
     */
    public void change_secret(String secret) throws IOException{
        if(identity_profile.local_user_name != null){
            API_Response response = api_channel.put(new User_Secret(identity_profile.local_user_name, secret));
            update_cached_profile(response);
        }
        else outcome = Outcome.ER_0005_Subject_user_name_was_never_associated;
    }

    /**
     * Change the user secret. Please refer to best practices with this
     * Formats the request, calls it via the api channel and updates the cached user profile
     * 
     * @param secret
     * @throws IOException
     */
    public API_Response unlock(String local_user_name) throws IOException{
            API_Response response = api_channel.put(new Unlock_Request(local_user_name));
            
            this.outcome = response.outcome;
            
            return response;
    }
    
    /**
     * Change the user secret. Please refer to best practices with this
     * Formats the request, calls it via the api channel and updates the cached user profile
     * 
     * @since v2
     * @param secret
     * @throws IOException
     */
    public API_Response create_intent(Intent_Type type, String local_user_name, String name, String email_address, String phone_number, String return_url, boolean strict_massl) throws IOException{
            return api_channel.put(new Intent(type, local_user_name, name, email_address, phone_number, return_url, strict_massl));
    }

    public API_Response create_intent(Intent_Type type, String local_user_name, String name, String email_address, String phone_number, String return_url) throws IOException{
            return create_intent(type, local_user_name, name, email_address, phone_number, return_url, false);
    }

    /**
     * Disclose use/possession of Personal Data Acquisition
     * 
     * Please see PII_Disclosure_Request documentation for formatting and normalization of data
     * 
     * @param amount
     * @throws IOException
     */
    public API_Response disclose_personal_data(String email_anchor, String phone_number_anchor, String pii_type, String value, long sample_count) throws IOException{
            return api_channel.put(new Personal_Data_Disclosure_Request(
                                                    identity_profile.local_user_name, 
                                                    email_anchor != null ? Identity_Plus_Utils.compute_sha_512(email_anchor.getBytes()) : null,
                                                    phone_number_anchor != null ? Identity_Plus_Utils.compute_sha_512(phone_number_anchor.getBytes()) : null,
                                                    pii_type, 
                                                    value == null ? null : Identity_Plus_Utils.compute_sha_512(value.getBytes()),
                                                    new BigInteger("" + sample_count)
                            ));
    }

    /**
     * Disclose deletion of personal data
     * 
     * Please see PII_Disclosure_Request documentation for formatting and normalization of data
     * 
     * @param amount
     * @throws IOException
     */
    public API_Response delete_personal_data(String email_anchor, String phone_number_anchor, String pii_type, String value) throws IOException{
            return api_channel.put(new Personal_Data_Disclosure_Request(
                                                    identity_profile.local_user_name, 
                                                    email_anchor != null ? Identity_Plus_Utils.compute_sha_512(email_anchor.getBytes()) : null,
                                                    phone_number_anchor != null ? Identity_Plus_Utils.compute_sha_512(phone_number_anchor.getBytes()) : null,
                                                    pii_type, 
                                                    value == null ? null : Identity_Plus_Utils.compute_sha_512(value.getBytes()),
                                                    BigInteger.ZERO
                            ));
    }

    
    public API_Response send_message(Message_Delivery_Request message_delivery_request) throws IOException{
            return api_channel.put(message_delivery_request);
    }
    
    /**
     * add trust to your local user.
     * Formats the request, calls it via the api channel and updates the cached user profile
     * 
     * @param amount
     * @throws IOException
     */
    public void put_trust(Object_Of_Trust trust_type) throws IOException{
            if(identity_profile.local_user_name != null){
                    API_Response response = api_channel.put(new Trust(identity_profile.local_user_name, serial_number, null, trust_type));
                    update_cached_profile(response);
            }
            else outcome = Outcome.ER_0005_Subject_user_name_was_never_associated;
    }
    
    /**
     * Disconnects the local user whose profile is cached
     * 
     * @throws IOException
     */
    public void disconnect_local_user() throws IOException{
        if(identity_profile.local_user_name != null){
                disconnect_local_user(identity_profile.local_user_name);
        }
        else outcome = Outcome.ER_0005_Subject_user_name_was_never_associated;
    }

    /**
     * Disconnects an arbitrary user. This is useful if you wish to delete users that are no longer with your service from
     * your identity + profile. There is no need to do a-priory certificate validation, all you need to know is the 
     * reference under which the user is bound.
     * 
     * @param local_user_uid
     * @throws IOException
     */
    public void disconnect_local_user(String local_user_uid) throws IOException{
        API_Response response = api_channel.delete(new Local_User_Reference(local_user_uid));
         update_cached_profile(response);
    }
}
