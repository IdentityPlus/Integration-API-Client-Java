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
 * The Identity_Inquiry wraps the request for identity Profile for a visiting for 
 * which the identity + anonymous id has been determined.
 * 
 * if the anonymous id cannot be determined the SSL way, the legacy redirect must be employed.
 * 
 * @author Stefan Harsan Farr
 */
public class Identity_Inquiry extends API_Request{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this request object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Identity_Inquiry.class);


    /**
     * The anonymous id extracted from the identity + certificate of the visitor
     * As of version 1.1, this field is no longer required if the serial number is specified 
     */
    public final String anonymous_id;


    /**
     * The certificate serial number, String encoded positive integer number
     * We will accept this as non mandatory during the migration period (v1 - v2)
     * As of version 2, we are going to use the serial number to identify clients, which in itself is a unique reference
     */
    public final String serial_number;

    /**
     * The anonymous id extracted from the identity + certificate of the visitor
     */
    public final String ip_address;

    public Identity_Inquiry(String serial_number, String anonymous_id, String ip_address) {
        if(anonymous_id == null && serial_number == null) throw new NullPointerException("either certificate_uid or serial number must be specified");

        this.ip_address = ip_address;
        this.anonymous_id = anonymous_id;
        this.serial_number = serial_number;
    }

    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Identity_Inquiry(JsonObject object){
        anonymous_id = null;
        ip_address = null;
        serial_number = null;
        restore_object(object);
    }
}
