// This file was generated by Mendix Studio Pro.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package communitycommons.actions;

import com.mendix.systemwideinterfaces.MendixRuntimeException;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import communitycommons.proxies.SanitizerPolicy;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;

/**
 * Removes all potential dangerous HTML from a string so that it can be safely displayed in a browser. 
 * 
 * This function should be applied to all HTML which is displayed in the browser, and can be entered by (untrusted) users.
 * 
 * - HTML: The html to sanitize
 * - policy1... policy6: one or more values of SanitizerPolicy. You may leave these policy parameters empty if you don't want to allow additional elements.
 * 
 * BLOCKS: Allows common block elements including <p>, <h1>, etc.
 * FORMATTING: Allows common formatting elements including <b>, <i>, etc.
 * IMAGES: Allows <img> elements from HTTP, HTTPS, and relative sources.
 * LINKS: Allows HTTP, HTTPS, MAILTO and relative links
 * STYLES: Allows certain safe CSS properties in style="..." attributes.
 * TABLES: Allows commons table elements.
 * 
 * For more information, visit:
 * 
 * http://javadoc.io/doc/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20180219.1
 */
public class XSSSanitize extends CustomJavaAction<java.lang.String>
{
	private java.lang.String html;
	private communitycommons.proxies.SanitizerPolicy policy1;
	private communitycommons.proxies.SanitizerPolicy policy2;
	private communitycommons.proxies.SanitizerPolicy policy3;
	private communitycommons.proxies.SanitizerPolicy policy4;
	private communitycommons.proxies.SanitizerPolicy policy5;
	private communitycommons.proxies.SanitizerPolicy policy6;

	public XSSSanitize(IContext context, java.lang.String html, java.lang.String policy1, java.lang.String policy2, java.lang.String policy3, java.lang.String policy4, java.lang.String policy5, java.lang.String policy6)
	{
		super(context);
		this.html = html;
		this.policy1 = policy1 == null ? null : communitycommons.proxies.SanitizerPolicy.valueOf(policy1);
		this.policy2 = policy2 == null ? null : communitycommons.proxies.SanitizerPolicy.valueOf(policy2);
		this.policy3 = policy3 == null ? null : communitycommons.proxies.SanitizerPolicy.valueOf(policy3);
		this.policy4 = policy4 == null ? null : communitycommons.proxies.SanitizerPolicy.valueOf(policy4);
		this.policy5 = policy5 == null ? null : communitycommons.proxies.SanitizerPolicy.valueOf(policy5);
		this.policy6 = policy6 == null ? null : communitycommons.proxies.SanitizerPolicy.valueOf(policy6);
	}

	@java.lang.Override
	public java.lang.String executeAction() throws Exception
	{
		// BEGIN USER CODE
		if (StringUtils.isEmpty(html)) {
			return "";
		}

		List<SanitizerPolicy> policyParams = Stream.of(policy1, policy2, policy3, policy4, policy5, policy6)
			.filter(Objects::nonNull)
			.collect(Collectors.toList());

		if (policyParams.isEmpty()) {
			throw new MendixRuntimeException("At least one policy is required");
		}

		return communitycommons.StringUtils.sanitizeHTML(html, policyParams);
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 * @return a string representation of this action
	 */
	@java.lang.Override
	public java.lang.String toString()
	{
		return "XSSSanitize";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
