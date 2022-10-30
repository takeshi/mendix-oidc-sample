package jwt.helpers;

public class RegisteredClaimIdentifier {
	
	public boolean identify(String claim) {
		if (
				claim.equals("iss") || 
				claim.equals("sub")	|| 
				claim.equals("exp") || 
				claim.equals("nbf")	|| 
				claim.equals("iat")	|| 
				claim.equals("jti") || 
				claim.equals("aud")
				) {
			return true;
		}
		return false;
	}

}
