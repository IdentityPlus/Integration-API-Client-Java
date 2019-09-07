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
 * The Agent Certificate Renewal request is used to issue certificates for Service Agents (Clients). 
 * This can happen in two ways,:
 * either the request is made for a valid previous certificate, in which a renewal procedure is executed,
 * or it needs to be performed with an initial secret and then an issuing is performed.
 * A service agent can rewnew its own certificate this way, but care must be taken as the previous certificate will be 
 * revoked uppon issuing the new one.
 * 
 * @author Stefan Harsan Farr
 */
public class Identity_Revocation_Request extends API_Request{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this request object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Identity_Revocation_Request.class);

    /**
     * Name of the agent to issue certificate for.
     * If the name exists, it will renew, otherwise it will create a new agent
     */
    public final String serial_number;
    
    public Identity_Revocation_Request(String serial_number){
            this.serial_number = serial_number;
    }

    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Identity_Revocation_Request(JsonObject object){
            this.serial_number = null;
            
            restore_object(object);
    }
}
