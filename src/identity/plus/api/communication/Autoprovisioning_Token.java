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
 * The User_Secret request deposits a secret string associated with the user within
 * the context of the client that makes the request. This secret will only be available to the 
 * client who deposited.  
 * 
 * @author Stefan Harsan Farr
 */
public class Autoprovisioning_Token extends API_Response{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this request object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Autoprovisioning_Token.class);

    /**
     * The local user name to to refer. This is only available within the context of the requesting API client 
     * which bound the user in the first place
     */
    public final String managed_service;
    
    /**
     * the secret to associate. This could be a password, an encryption key,etc.
     */
    public final String token;
    
    public Autoprovisioning_Token(String managed_service, String token) {
        if(managed_service == null || token == null) throw new NullPointerException("Both, the managed service and the token must be specified");
        this.managed_service = managed_service;
        this.token = token;
    }

    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Autoprovisioning_Token(JsonObject object){
        this.managed_service = null;
        this.token = null;
        
        restore_object(object);
    }
}
