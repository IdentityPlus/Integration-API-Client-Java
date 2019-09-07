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

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;

/**
 * The core response for most request containing a reference number
 * It comes in response to a call that requires a reference number such as an intrusion report
 * 
 * @author Stefan Harsan Farr
 */
public class Service_Identity extends API_Response{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this response object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Service_Identity.class);
   
    /**
     * p12 certificate format
     */
    public final byte[] p12;

    /**
     * Password for the p12 format
     */
    public final String password;

    /**
     * PEM encoded certificate
     */
    public final byte[] certificate;
    
    /**
     * PEM encoded private key
     */
    public final byte[] private_key;
    
    
    public Service_Identity(Outcome response, byte[] p12, String password, byte[] certificate, byte[] private_key) {
        super(response);
        this.p12 = p12;
        this.password = password;
        this.certificate = certificate;
        this.private_key = private_key;
    }

    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Service_Identity(JsonObject object){
        // initialize fields to null
        this.p12 = null;
        this.password = null;
        this.certificate = null;
        this.private_key = null;
        
        // call the restore mechanism
        restore_object(object);
    }
}
