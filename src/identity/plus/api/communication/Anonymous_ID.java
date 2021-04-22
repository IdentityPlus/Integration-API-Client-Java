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
 * The Anonymous_ID is part of the Legacy HTTP call assembly.
 * This response comes URL encoded as part of the redirect when the the 
 * identity + service is used to read the client certificate from the user browser.  
 *
 * This Object is only needed by implementations that use the identity + service over
 * http or do not have access to reading the SSL Client certificate for other reasons
 * 
 * This object will always come encrypted with the API Client's public key
 * 
 * @author Stefan Harsan Farr
 */
public class Anonymous_ID extends API_Response{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this response object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Anonymous_ID.class);
        
    /**
     * The anonymous id as identified by the identity+ api
     */
    public final String anonymous_id;
    
    /**
     * The serial number of the certificate as identified by the identity+ api
     */
    public final String serial_number;

    /**
     * This is a random sequence of text which is not needed as part of the identity + 
     * processes and can be discarded.
     * 
     * It's sole purpose is to force different encryption outputs for responses with the
     * same value. We use 16 characters, but normally even one character would suffice
     * to change the output of the encrypted bytes. 
     */
    public final String salt;
    
    public Anonymous_ID(Outcome response, String anonymous_id, String serial_number){
        super(response);
        
        if(anonymous_id == null) throw new NullPointerException("anonymous_id cannot be null");
        if(serial_number == null) throw new NullPointerException("serial_number cannot be null");
        
        this.anonymous_id = anonymous_id;
        this.serial_number = serial_number;
        this.salt = Identity_Plus_Utils.random_text(16);
    }

    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Anonymous_ID(JsonObject object){
        // initialize fields to null
        this.anonymous_id = null;
        this.salt = null;
        this.serial_number = null;
        
        // call the JSON restore method
        restore_object(object);
    }
}
