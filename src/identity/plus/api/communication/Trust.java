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
import identity.plus.api.Object_Of_Trust;

/**
 * The Trust request deposits a certain amount of trust with the user within
 * the context of the client that makes the request. This trust will only be available to any
 * client requesting the profile of the user.
 * 
 * @author Stefan Harsan Farr
 */
public class Trust extends API_Request{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this request object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Trust.class);

    /**
     * The anonymous id to refer. This is only available when the Identity + account is not bound to local user
     */
    public final String local_user_name;
    
    /**
     * The local user name to refer. This is only available within the context of the requesting API client 
     * which bound the user in the first place
     */
    public final String anonymous_id;

    /**
     * The certificate serial number, String encoded positive integer number
     * We will accept this as non mandatory during the migration period (v1 - v2)
     * As of version 2, we are going to use the serial number to identify clients, which in itself is a unique reference
     */
    public final String serial_number;

    /**
     * The amount of trust tokens to associate.
     * A default of 10 trust points are automatically associated upon user binding.
     * The maximum amount of trust points that one service can associate with an identity
     * is 10000.
     */
    public final Object_Of_Trust trust_type;
    
    public Trust(String local_user_name, String serial_number, String anonymous_id, Object_Of_Trust trust_type) {
        if(local_user_name == null && anonymous_id == null) throw new NullPointerException("Local user name or anonymous id must be specified");
        this.local_user_name = local_user_name;
        this.anonymous_id = anonymous_id;
        this.serial_number = serial_number;
        this.trust_type = trust_type == null ? Object_Of_Trust.random : trust_type;
    }

    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Trust(JsonObject object){
        this.local_user_name = null;
        this.anonymous_id = null;
        this.trust_type = null;
        serial_number = null;
        
        restore_object(object);
    }
}
