package plus.identity.service.agent;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import plus.identity.service.agent.responses.IDP_Block;
import plus.identity.service.agent.responses.IDP_Error;
import plus.identity.service.agent.responses.IDP_Impossible;
import plus.identity.service.agent.responses.IDP_OK;
import plus.identity.service.agent.responses.IDP_Redirect;
import plus.identity.service.agent.responses.IDP_Response;



public class V2 {
    public final String end_point;
    private final SSLSocketFactory socket_factory;
    
    public V2(String end_point, InputStream p_12_stream, String password, InputStream trusted_ca_stream) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, KeyManagementException {
            this.end_point = end_point;
    
            TrustManagerFactory tmf = null;
            KeyManagerFactory kmf = null;
            
            if(trusted_ca_stream != null) {
                    CertificateFactory cert_factory = CertificateFactory.getInstance("X509");
                    Collection<? extends Certificate> ca_list = cert_factory.generateCertificates(trusted_ca_stream);
                    KeyStore trust_store = KeyStore.getInstance("JKS");
                    trust_store.load(null, null);
                    for(Certificate ca : ca_list) {
                            System.out.println("trusting authority: " + ((X509Certificate)ca).getSubjectX500Principal().getName());
                            trust_store.setCertificateEntry(((X509Certificate)ca).getSubjectX500Principal().getName(), ca);
                    }
                    
                    tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init(trust_store);
            }
            else System.out.println("trusting authority: all system default");
            
            if (p_12_stream != null){
                    KeyStore ks = KeyStore.getInstance("PKCS12");
                    ks.load(p_12_stream, password.toCharArray());
                    // ks.setKeyEntry(certificate_alias, private_key, null, certificate_chain);
        
                    kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                    kmf.init(ks, password.toCharArray());
                    SSLContext ssl_ctx = SSLContext.getInstance("TLS");
                    ssl_ctx.init(kmf.getKeyManagers(), tmf != null ? tmf.getTrustManagers() : null , null);
            }
    
            SSLContext ssl_ctx = SSLContext.getInstance("TLS");
            ssl_ctx.init(kmf != null ? kmf.getKeyManagers() : null, tmf != null ? tmf.getTrustManagers() : null , null);
            
            socket_factory = ssl_ctx.getSocketFactory();
    }
    
    public IDP_Response get(String operation, String ... parameters) throws IOException{
            StringBuilder query_string = new StringBuilder();
            for(int i = 0; i < parameters.length; i++) {
                    query_string.append(query_string.length() == 0 ? "?" : "&");
                    query_string.append("p");
                    query_string.append(i);
                    query_string.append("=");
                    query_string.append(URLEncoder.encode(parameters[i], "UTF-8"));
            }
            
            URL endpoint = new URL(end_point + "/v2/" + operation + query_string);

            return call(endpoint, "GET", null);
    }

    public IDP_Response post(String operation, JsonObject arguments) throws IOException{
            URL endpoint = new URL(end_point + "/v2/" + operation);
            return call(endpoint, "POST", arguments.toString());
    }

    private IDP_Response call(URL url, String method, String body) throws IOException{
            HttpsURLConnection connection = (HttpsURLConnection)url.openConnection();
            connection.setSSLSocketFactory(socket_factory);

            connection.setRequestMethod(method);
            
            if(body != null) {
                    connection.setDoOutput(true);
                    OutputStreamWriter wr = new OutputStreamWriter(connection.getOutputStream());
                    wr.write(body);
                    wr.flush();
            }
            else connection.setDoOutput(false);

            int response_code = connection.getResponseCode();

            if(IDP_Response.is_block(response_code)) return new IDP_Block();
            else if(IDP_Response.is_redirect(response_code)) return new IDP_Redirect(response_code, connection.getHeaderField("Location"));
            else if(IDP_Response.is_impossible(response_code)) return new IDP_Impossible(response_code, new String(drain(connection.getInputStream())));
            else if(IDP_Response.is_error(response_code)) return new IDP_Error(response_code, connection.getContent().toString());
            else {
                    JsonReader reader = Json.createReader(connection.getInputStream());
                    JsonObject jsso = reader.readObject();
                    
                    return new IDP_OK(response_code, jsso);
            }
    }
    
    public static byte[] drain(InputStream is) throws IOException{
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
    
            int len = is.read(buffer);
    
            while(len > 0){
                bos.write(buffer, 0, len);
                len = is.read(buffer);
            }
    
            return bos.toByteArray();
    }
    
    public static void main(String[] args) throws Exception{
        JsonReader json_reader = Json.createReader(new FileInputStream("/etc/the-social-protocol/api-client.json"));
        JsonObject json = json_reader.readObject();
        
        // we instantiate the channel and cache it
        V2 api = new V2(json.getString("api-endpoint"), new FileInputStream(json.getString("certificate")), json.getString("password"), new FileInputStream("/media/Work/Testing/sp/second/ca.pem"));
        
        api.get("identity-profile", "08179BDF9463F75C");
    }
}
