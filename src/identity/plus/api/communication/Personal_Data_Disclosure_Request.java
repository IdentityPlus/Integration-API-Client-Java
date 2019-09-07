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

import identity.plus.api.Identity_Plus_Utils;

/**
 * Disclosure of use of personal information about a user bound with a certain local user id
 * 
 * @author Stefan Harsan Farr
 */
public class Personal_Data_Disclosure_Request extends API_Request{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this request object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Personal_Data_Disclosure_Request.class);

    /**
     * The anonymous id to refer. This is only available when the Identity + account is not bound to local user
     */
    public final String local_user_name;
    
    /**
     * The email anchor given in form of SHA 512 of the email address of the person who's PII is being stored.
     * This should be used when there is no local user name associated
     * The SHA 512 is computed on the fully lowercase email address with no leading or trailing spaces, for consistent results, example:
     * username@example.com
     */
    public final byte[] email_sha_anchor;

    /**
     * The phone number anchor given in form of SHA 512 of the actual phone number of the person who's PII is being stored.
     * This should be used when there is no local user, or email associated
     * The SHA 512 is computed after normalizing the phone number by removing all spaces, punctuations and using + instead of 00  before country code, example:
     * +CCPRFNUMBER (+12123123456)
     */
    public final byte[] phone_number_sha_anchor;
    
    /**
     * The designation of the personally identifiable data-point in English language in simple semantical form. Example:
     * first name, last name, name, email address, phone number, picture, date of birth, IP address, address, credit card number, social security number, etc.
     */
    public final String pii_type;

    /**
     * The SHA 512 of the PII data-point
     * Data should be normalized before computing the SHA for consistent results
     *         - unless the case is strict, all data-points should be lowercased before computing the SHA
     *         - there should be no trailing or leading spaces to the text, unless required by the format
     *         - all punctuation should be replaced with space, unless it uses a strict format like IP address: 123.123.123.123
     *         - there should be no double spaces anywhere in the text, unless a strict formatting is required
     *         
     * A few data points formatting suggestions:
     *         Phone number: +CCPRFNUMBER (+12123123456)
     *         IP Address: XXX.XXX.XXX.XXX
     *         Email Address: username@example.com
     *         Dates: yyyymmdd (19770213)
     *         Postal Addresses should be submitted separately as: country, state/county/region, city, street address, zip/postal code
     *         User Name: username (all lowercase unless it is case sensitive locally
     *         
     * Only data-points that are comparable in hashed form (like those above) should be hashed. Passwords or other hashed or encrypted information, 
     * time series data, images or other biometric information that are resource intensive to hash or are not comparable with similar data samples in hashed form,
     * should not be hashed
     */
    public final byte[] sha_512;

    /**
     * Number of samples held on the specific data-point.
     * This makes sense for all those data-points that are not hashed.
     */
    public final BigInteger sample_count;
    
    public Personal_Data_Disclosure_Request(String local_user_name, byte[] email_sha_anchor, byte[] phone_number_sha_anchor, String pii_type, byte[] sha_512, BigInteger sample_count) {
        if(local_user_name == null && email_sha_anchor == null && phone_number_sha_anchor == null) throw new NullPointerException("Either local user name, phone_number_sha_anchor or email_sha_anchor must be specified");
        this.local_user_name = local_user_name;
        this.email_sha_anchor = email_sha_anchor;
        this.phone_number_sha_anchor = phone_number_sha_anchor;
        this.pii_type = pii_type;
        this.sha_512 = sha_512;
        this.sample_count = sample_count;
    }

    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Personal_Data_Disclosure_Request(JsonObject object){
        this.local_user_name = null;
        this.email_sha_anchor = null;
        this.phone_number_sha_anchor = null;
        this.pii_type = null;
        this.sha_512 = null;
        this.sample_count = BigInteger.ZERO;
        
        restore_object(object);
    }
}
