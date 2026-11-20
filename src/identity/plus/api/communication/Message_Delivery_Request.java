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

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;
import identity.plus.api.json.API_Object;
import identity.plus.api.json.API_Request;
import identity.plus.api.json.Json_Codec;

/**
 * Delivers a message to users of a service, identified by the local user names bound to the service.
 *
 * @param recipients    the local user names to send the message to; only resolvable when the identity +
 *                      account is bound to a local user. Never null.
 * @param subject_line  the message subject line
 * @param impact        classification of the nature of the information, by impact
 * @param thumbnail     thumbnail image, PNG or JPG encoded
 * @param brief         a short description of what the message is about
 * @param url           the online version of the message
 * @param action        what the user needs to do about the message
 * @param expiry        if set, the message is deleted at this time and the user can no longer view or act on it.
 *                      Given in GMT; shown to the user in their local time.
 * @param custom        additional fields, sent as-is
 *
 * @author Stefan Harsan Farr
 */
public record Message_Delivery_Request(
        List<String> recipients,
        String subject_line,
        String impact,
        byte[] thumbnail,
        String brief,
        String url,
        String action,
        Date expiry,
        Map<String, String> custom
) implements API_Request {

    /**
     * The JSON Name of this request object as sent to the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Message_Delivery_Request.class);

    public Message_Delivery_Request {
        recipients = recipients == null ? List.of() : List.copyOf(recipients);
        thumbnail  = thumbnail == null ? null : thumbnail.clone();
        expiry     = expiry == null ? null : new Date(expiry.getTime());
        custom     = API_Object.custom_of(custom);
    }

    public Message_Delivery_Request(List<String> recipients, String subject_line, String impact, byte[] thumbnail,
                                    String brief, String url, String action, Date expiry) {
        this(recipients, subject_line, impact, thumbnail, brief, url, action, expiry, null);
    }

    public static Message_Delivery_Request from_json(JsonObject object) {
        return Json_Codec.decode(Message_Delivery_Request.class, object);
    }

    @Override public byte[] thumbnail() { return thumbnail == null ? null : thumbnail.clone(); }
    @Override public Date expiry()      { return expiry == null ? null : new Date(expiry.getTime()); }

    @Override
    public boolean equals(Object o) {
        return o instanceof Message_Delivery_Request m
            && recipients.equals(m.recipients)
            && Objects.equals(subject_line, m.subject_line)
            && Objects.equals(impact, m.impact)
            && Arrays.equals(thumbnail, m.thumbnail)
            && Objects.equals(brief, m.brief)
            && Objects.equals(url, m.url)
            && Objects.equals(action, m.action)
            && Objects.equals(expiry, m.expiry)
            && custom.equals(m.custom);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(recipients, subject_line, impact, brief, url, action, expiry, custom)
             + Arrays.hashCode(thumbnail);
    }

    @Override
    public String toString() {
        return "Message_Delivery_Request[recipients=" + recipients.size()
             + ", subject_line=" + subject_line
             + ", impact=" + impact
             + ", thumbnail=" + (thumbnail == null ? "null" : thumbnail.length + " bytes")
             + ", expiry=" + expiry + "]";
    }
}