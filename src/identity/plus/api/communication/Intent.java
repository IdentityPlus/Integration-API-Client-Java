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
package identity.plus.api.communication;

import java.math.BigInteger;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;

/**
 * The Intent request initiates an out of bound operation with Identity Plus. A context is created and the user is redirected to identity plus to handle the operation.
 * On the server side, intents are very short lived objects. They need to be followed through within 30s, otherwise they expire.
 * 
 * @since v2
 * @author Stefan Harsan Farr
 */
public class Intent extends API_Request{
    private static final long serialVersionUID = 1L;
    
    /**
     * the type of the intent can be one of { discover, register, bind}. empty defaults to "discover"
     */
    public final Intent_Type type;

    /**
     * The JSON Name of this request object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Intent.class);

    /**
     * The local user name to to refer, if any
     */
    public final String local_user_name;
    
    /**
     * the URL to return to after the intent has been completed. The page at the URL needs to accept the encrypted Identity_Profile response
     * if the URL is not specified identity plus will default to the landing page of the domain the API is authenticating into
     */
    public final String return_url;
    
    /**
     * the email address of the local user (information sharing scenario)
     */
    public final String email_address;
    
    /**
     * the phone number of the local user (information sharing scenario)
     */
    public final String phone_number;

    /**
     * the name of the local user (information sharing scenario)
     */
    public final String name;
    
    /**
     * How long is this user a member of the service requesting the association.
     * the age in days of the local account in other words.
     */
    public final BigInteger local_user_age;

    /**
     * If the client specifies strict MASSL, then identity plus will not return an intent reference as 
     * part of the return URL when redirecting. It will be assumed that the requesting server requires strict
     * use of Mutually Authenticated SSL, and as such, it has all the access to the user's session via the 
     * details found in the client certificate and via back-end API request
     */
    public final Boolean strict_massl;
    
    /**
     * the name of the local user (information sharing scenario)
     */
    public final String service_name;

    public Intent(Intent_Type type) {
        this(type, null, null, null, null, new BigInteger("0"), null, true);
    }

    public Intent(Intent_Type type, String local_user_name, String name, String email_address, String phone_number, String return_url, boolean strict_massl) {
        this(type, local_user_name, name, email_address, phone_number, new BigInteger("0"), return_url, strict_massl);
    }
    
    public Intent(Intent_Type type, String local_user_name, String name, String email_address, String phone_number, BigInteger local_user_age, String return_url, boolean strict_massl) {
        this.strict_massl = strict_massl;
        this.type = type == null ? Intent_Type.discover : type;
        this.local_user_name = local_user_name == null ? "" : local_user_name;
        this.return_url = return_url == null ? "" : return_url;
        this.name = name == null ? "" : name;
        this.local_user_age = local_user_age;
        this.email_address = email_address == null ? "" : email_address;
        this.phone_number = phone_number == null ? "" : phone_number;
        this.service_name = "";
    }

    public Intent(Intent_Type type, String service, String local_user_name, String name, String email_address, String phone_number, BigInteger local_user_age, String return_url, boolean strict_massl) {
        this.strict_massl = strict_massl;
        this.type = type == null ? Intent_Type.discover : type;
        this.local_user_name = local_user_name == null ? "" : local_user_name;
        this.return_url = return_url == null ? "" : return_url;
        this.name = name == null ? "" : name;
        this.local_user_age = local_user_age;
        this.email_address = email_address == null ? "" : email_address;
        this.phone_number = phone_number == null ? "" : phone_number;
        this.service_name = service == null ? "" : service;
    }
    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Intent(JsonObject object){
        this.strict_massl = null;
        this.local_user_name = null;
        this.return_url = null;
        this.type = null;
        this.email_address = null;
        this.name = null;
        this.phone_number = null;
        this.local_user_age = null;
        this.service_name = null;
        
        restore_object(object);
    }
}
