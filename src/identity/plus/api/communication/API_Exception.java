package identity.plus.api.communication;

public class API_Exception extends Exception{
    public final Outcome outcome;
    
    public API_Exception(Outcome outcome){
        this.outcome = outcome;
    }
}
