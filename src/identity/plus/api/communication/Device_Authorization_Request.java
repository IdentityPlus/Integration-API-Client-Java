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
 * The Device Authorization Request creates an authorization token which allows the user to jump
 * directly to the device authorization step. It essentially provides sufficient proof of Identity
 * for Identityplus to not trigger more verification steps. In other words, it allows a third party
 * to provide proof of identity such that their user would be able to recover their identityplus
 * account should they be left with no certified devices and all access to their account or are left.
 *  
 * There are prerequisites for this action to be successful:
 * - A service can only provide authorization requests to their own users
 * - These users must have their identityplus accounts bound with their local service accounts
 * - The user must authorize the service to perform such an action in their identityplus profile
 * - Only organizations that can provide either KYC-d or in-person identity assurance with their clients,
 *   can perform this operation
 * 
 * @author Stefan Harsan Farr
 */
public class Device_Authorization_Request extends API_Request{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this request object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Device_Authorization_Request.class);

    /**
     * The anonymous id to refer. This is only available when the Identity + account is not bound to local user
     */
    public final String local_user_name;
    
    public Device_Authorization_Request(String local_user_name) {
        if(local_user_name == null) throw new NullPointerException("Local user name must be specified");
        this.local_user_name = local_user_name;
    }

    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Device_Authorization_Request(JsonObject object){
        this.local_user_name = null;
        
        restore_object(object);
    }
}
