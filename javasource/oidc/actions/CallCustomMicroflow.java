// This file was generated by Mendix Studio Pro.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package oidc.actions;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import com.mendix.systemwideinterfaces.core.IMendixObject;

public class CallCustomMicroflow extends CustomJavaAction<java.lang.Boolean>
{
	private java.lang.String Microflow;
	private IMendixObject __Account;
	private administration.proxies.Account Account;

	public CallCustomMicroflow(IContext context, java.lang.String Microflow, IMendixObject Account)
	{
		super(context);
		this.Microflow = Microflow;
		this.__Account = Account;
	}

	@java.lang.Override
	public java.lang.Boolean executeAction() throws Exception
	{
		this.Account = this.__Account == null ? null : administration.proxies.Account.initialize(getContext(), __Account);

		// BEGIN USER CODE
		// ILogNode logger=Core.getLogger("OIDC.LogNode");
		IContext context=getContext();
		Boolean microflowResult = Core.microflowCall(Microflow)
    	.withParam("Account", __Account)
    	.execute(context);
		if (microflowResult == false) {
			logger.error("Custom microflow implementation should be required to process Access_token roles.");
		}
		return microflowResult;
		
		//throw new com.mendix.systemwideinterfaces.MendixRuntimeException("Java action was not implemented");
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 * @return a string representation of this action
	 */
	@java.lang.Override
	public java.lang.String toString()
	{
		return "CallCustomMicroflow";
	}

	// BEGIN EXTRA CODE
	private static final ILogNode logger=Core.getLogger("OIDC.LogNode");
	// END EXTRA CODE
}
