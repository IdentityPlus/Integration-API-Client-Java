package plus.identity.service.agent.responses;

public class IDP_Redirect extends IDP_Response{
    public final String location;
    
    public IDP_Redirect(int code, String lcoation){
            super(code);
            this.location = lcoation;
    }
}
