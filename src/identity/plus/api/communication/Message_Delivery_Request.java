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

import java.util.Date;
import java.util.List;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;

/**
 * Delivers a message to a user of a service identified by the local user bound the the services
 * 
 * @author Stefan Harsan Farr
 */
public class Message_Delivery_Request extends API_Request{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this request object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Message_Delivery_Request.class);

    /**
     * The list of anonymous local user names to send the message to. These are only available when the Identity + account is bound to local user.
     */
    public final List<String> recipients;
    
    /**
     * Thumbnail image PNG or JPG encoded
     */
    public final byte[] thumbnail;

    /**
     * Message subject line
     */
    public final String subject_line;
    
    /**
     * Classification of the nature the information, by impact
     */
    public final String impact;

    /**
     * A short description of the what the message is about
     */
    public final String brief;

    /**
     * The online version of the message
     */
    public final String url;

    /**
     * what the message is about, what the user needs to do about it: read it, 
     */
    public final String action;

    /**
     * If the message is set to expire at a certain date, it will be deleted at that date and the user can no longer view it or act upon it
     * Time should be given into GMT time and will be translated to user local
     */
    public final Date expiry;
    

    public Message_Delivery_Request(List<String> local_user_name, String subject_line, String impact, byte[] thumbnail, String brief, String url, String action, Date expiry) {
            this.recipients = local_user_name;
            this.impact = impact;
            this.thumbnail = thumbnail;
            this.subject_line = subject_line;
            this.brief = brief;
            this.url = url;
            this.action = action;
            this.expiry = expiry;
    }


    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Message_Delivery_Request(JsonObject object){
        this.recipients = null;
        this.impact = null;
        this.thumbnail = null;
        this.subject_line = null;
        this.brief = null;
        this.url = null;
        this.action = null;
        this.expiry = null;
        
        restore_object(object);
    }
}
