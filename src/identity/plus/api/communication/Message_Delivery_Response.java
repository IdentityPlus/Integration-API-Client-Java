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
import java.util.List;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;

/**
 * Message delivery sumary
 * 
 * @author Stefan Harsan Farr
 */
public class Message_Delivery_Response extends API_Response{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this response object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Message_Delivery_Response.class);
   
    /**
     * The reference number value
     */
    public final BigInteger message_reference;
    
    /**
     * The reference number value
     */
    public final List<String> failed_recipients;
    
    public Message_Delivery_Response(Outcome response, BigInteger message_reference, List<String> failed_recipients) {
        super(response);
        this.message_reference = message_reference;
        this.failed_recipients = failed_recipients;
    }

    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Message_Delivery_Response(JsonObject object){
        // initialize fields to null
        this.message_reference = null;
        this.failed_recipients = null;
        // call the restore mechanism
        restore_object(object);
    }
}
