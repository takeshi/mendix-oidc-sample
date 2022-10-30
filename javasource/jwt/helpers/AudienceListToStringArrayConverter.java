package jwt.helpers;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.mendix.core.Core;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;

import jwt.proxies.Audience;
import jwt.proxies.JWT;

public class AudienceListToStringArrayConverter {
	
	public String[] convert(IContext context, JWT jwt) {
		List<IMendixObject> audiences = Core.retrieveByPath(context, jwt.getMendixObject(), "JWT.Audience_JWT");

		Iterator<IMendixObject> audienceIterator = audiences.iterator();
		
		List<String> audienceList = new ArrayList<String>();
		
		while(audienceIterator.hasNext()) {
			IMendixObject audienceObject = audienceIterator.next();
			Audience audience = Audience.initialize(context, audienceObject);
			audienceList.add(audience.getaud());
		}
		
		return audienceList.toArray(new String[audienceList.size()]);
	}
}
