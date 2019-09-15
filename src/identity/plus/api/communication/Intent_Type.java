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

/**
 * The Intent type specifies what operation should identity plus perform for the user upon redirect.
 * these operations are performed on devices that do not bear valid certificates and hence they need to be redirected to identity plus
 *
 * @since v2
 * @author Stefan Harsan Farr
 */
public enum Intent_Type {
    /* Validate the certificate and return. This essentially tells identityplus that the service was able to read the certificate but got needs validation error over API */
    validate, 

    /* check if the device has a certificate. This is usually necessary if the site cannot read the certificate itself. No action will be performed if certificate is not found */
    discover, 

    /* request this device to be certified. Connect device or sign up for identity plus if necessary. The operation will be performed under the brand of the domain */
    request, 

    /* request this device to be certified and bind local user to it. Connect device or sign up for identity plus if necessary. The operation will be performed under the brand of the domain */
    bind,

    /* request this device to be certified and bind local user to it. Connect device or sign up for identity plus if necessary. The operation will be performed under the brand of the domain */
    assume_ownership;
}
