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

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;

/**
 * The core response for most request containing all the profile information
 * necessary.
 * 
 * @author Stefan Harsan Farr
 */
public class Identity_Profile extends API_Response{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this response object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Identity_Profile.class);
    
    /**
     * The local user id that was bound with the identity+ account to which the validated 
     * anonymous id belongs to, if any.
     * 
     * In case no local user id was bound to the identity + account by the requesting API Client
     * this field will be empty.
     */
    public final String local_user_name;
    public final String local_user_id;

    /**
     * A list of web sites which the user chose as trust sponsors. An empty list can mean
     * new user, user chose to not advertise presence on any sites, or a bot
     */
    public final List<String> service_roles;

    /**
     * The local user secret that was bound with the identity+ account to which the validated 
     * anonymous id belongs to, if any.
     * 
     * In case no secret was bound to the identity + account by the requesting API Client
     * this field will be empty.
     */
    public final String user_secret;
    
    /**
     * A list of web sites which the user chose as trust sponsors. An empty list can mean
     * new user, user chose to not advertise presence on any sites, or a bot
     */
    public final List<String> trust_sponsors;
    
    /**
     * The number of sites this identity is bound. This is just a number it does not contain specifics
     */
    public final BigInteger sites_frequented;
    
    /**
     * The average age of the accounts over the sites the identity has an account with 
     */
    public final BigInteger average_identity_age;

    /**
     * The maximum age of the accounts over the sites the identity has an account with 
     */
    public final BigInteger max_identity_age;

    /**
     * In case this was an out of band authorization, the id of the certificate that made the authorization
     */
    public final BigInteger authorizing_certificate;

    /**
     * Trust score, as computed by identity +. This is a logarithmic value and cannot be larger than 5.
     * see trust score analysis on the https://identity.plus/resources/api-best-practices for details 
     */
    public final BigDecimal trust_score;
    
    /**
     * The total number of trust awarded to this identity + user by the api client 
     */
    public final BigInteger local_trust;
    
    /**
     * The total number of trust awarded to this identity + user by the api client 
     */
    public final BigInteger local_intrusions;

    /**
     * Your guarantees
     */
    public final List<String> your_guarantees;
    
    /**
     * Your guarantees
     */
    public final List<String> community_guarantees;

    public Identity_Profile(Outcome response, String local_user_name, String[] service_roles, String user_secret, String[] trust_sponsors, BigInteger sites_frequented, BigInteger average_identity_age, BigInteger max_identity_age, BigDecimal trust_score, BigInteger local_trust, BigInteger local_intrusions, BigInteger authorizing_certificate, String[] your_guarantees, String[] community_guarantees) {
        super(response);
        
        if(trust_sponsors == null) throw new NullPointerException("Neither value can be null");
        
        this.local_user_name = local_user_name;
        this.local_user_id = local_user_name;
        this.user_secret = user_secret;
        this.trust_sponsors = Collections.unmodifiableList(Arrays.asList(trust_sponsors));
        this.service_roles = Collections.unmodifiableList(Arrays.asList(service_roles));
        this.sites_frequented = sites_frequented;
        this.average_identity_age = average_identity_age;
        this.max_identity_age = max_identity_age;
        this.trust_score = trust_score;
        this.local_trust = local_trust;
        this.local_intrusions = local_intrusions;
        this.authorizing_certificate = authorizing_certificate;
        this.your_guarantees = Collections.unmodifiableList(Arrays.asList(your_guarantees));
        this.community_guarantees = Collections.unmodifiableList(Arrays.asList(community_guarantees));
    }

    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Identity_Profile(JsonObject object){
        // initialize fields to null
        this.local_user_name = null;
        this.local_user_id = null;
        this.service_roles = null;
        this.user_secret = null;
        this.trust_sponsors = null;
        this.sites_frequented = null;
        this.average_identity_age = null;
        this.max_identity_age = null;
        this.trust_score = null;
        this.local_trust = null;
        this.local_intrusions = null;
        this.authorizing_certificate = null;
        this.your_guarantees = null;
        this.community_guarantees = null;
        
        // call the restore mechanism
        restore_object(object);
    }
}
