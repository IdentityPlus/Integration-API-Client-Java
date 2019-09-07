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

import identity.plus.api.Identity_Assurance;
import identity.plus.api.Identity_Plus_Utils;

/**
 * The Local_User_Information request deposits the the details of a user local to the client service within
 * the context of the client that makes the request. This can only be done once for a user.
 * 
 * @author Stefan Harsan Farr
 */
public class Local_User_Information extends API_Request{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this request object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Local_User_Information.class);

    /**
     * The anonymous id extracted from the identity + certificate of the visitor.
     * at this stage identity + is not yet aware of the association, therefore it cannot search for the user name
     */
    public final String anonymous_id;

    /**
     * The certificate serial number, String encoded positive integer number
     * We will accept this as non mandatory during the migration period (v1 - v2)
     * As of version 2, we are going to use the serial number to identify clients, which in itself is a unique reference
     */
    public final String serial_number;
    
    /**
     * How long is this user a member of the service requesting the association.
     * the age in days of the local account in other words.
     */
    public final BigInteger local_user_age;
    
    /**
     * A unique identifier that binds the local user to the identity.
     * it is recommended you don't use the user name, but rather a different random set of string such as user id
     * in any case, this information is only be accessible to the service binding the user
     */
    public final String local_user_name;
    
    /**
     * The amount of initial trust tokens to associate.
     * A default of 10 trust points are automatically associated upon user binding.
     * The maximum amount of trust points that one service can associate with an identity
     * is 10000.
     */
    public final BigInteger tokens_of_trust;
    
    /**
     * The level of assurance the service can provide relative to the user they intend to bind
     */
    public final Identity_Assurance identity_assurance;
    
    
    public Local_User_Information(String anonymous_id, String serial_number, String local_user_name, BigInteger local_user_age, BigInteger tokes_of_trust) {
        this(anonymous_id, serial_number, local_user_name, local_user_age, tokes_of_trust, null);
    }

    public Local_User_Information(String anonymous_id, String serial_number, String local_user_name, BigInteger local_user_age, BigInteger tokes_of_trust, Identity_Assurance assurance) {
        if(anonymous_id == null && serial_number == null || local_user_name == null) throw new NullPointerException("Neither value can be null");

        this.identity_assurance = assurance == null ? Identity_Assurance.none : assurance;
        this.local_user_name = local_user_name;
        this.tokens_of_trust = tokes_of_trust == null ? BigInteger.ZERO : tokes_of_trust;
        this.anonymous_id = anonymous_id;
        this.local_user_age = local_user_age;
        this.serial_number = serial_number;
    }

    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Local_User_Information(JsonObject object){
        this.local_user_name = null;
        this.tokens_of_trust = null;
        this.anonymous_id = null;
        this.local_user_age = null;
        this.serial_number = null;
        this.identity_assurance = null;
        
        restore_object(object);
    }
}
