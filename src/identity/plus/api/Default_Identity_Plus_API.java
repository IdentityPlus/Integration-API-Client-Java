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
package identity.plus.api;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

/**
 * The default Identity + API which stores session attributes the 
 * default way, in the default java session
 *  
 * @author Stefan Harsan Farr
 */
public class Default_Identity_Plus_API extends Identity_Plus_API {
    public Default_Identity_Plus_API(API_Channel idp_client, HttpServletRequest request, boolean skip_legacy_call) throws IOException {
        super(idp_client, request, skip_legacy_call);
    }
    
    /**
     * Default implementation for the session attribute recovery
     */
    @Override
    protected Object get_session_variable(String key) {
        return http_request.getSession(true).getAttribute(key);
    }
    
    /**
     * Default implementation for the session attribute storing
     */
    @Override
    protected void set_session_variable(String key, Object value) {
        http_request.getSession(true).setAttribute(key, value);
    }
}
