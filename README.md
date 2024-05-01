# Table of References

Well this is a repo that I use for creating/reporting issues to clients during day2day works and maybe bugbounty.<br>
It's just an compressed information used to find links and infos easier!<br>
During creation of issues, we need to report CWE ID, References for Help, OWASP ID and more.<br>
> __[!!!] THIS IS NOT ABSOLUTELY TRUE/CORRECT__, if you see that something is wrong, please point it for me!
<br>
<br>
<!-- We start the references here, divided by issue types -->

<details>
  <summary>2FA Susceptible to Brute Force</summary>
  
    - Common Weakness Enumeration:
    CWE-307: Improper Restriction of Excessive Authentication Attempts

    - References:
    https://www.infosecinstitute.com/resources/hacking/ethical-hacking-top-6-techniques-for-attacking-two-factor-authentication
    https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>AWS Cognito Self Signup</summary>
  
    - Common Weakness Enumeration:
    CWE-285: Improper Authorization

    - References:
    https://shellmates.medium.com/amazon-cognito-misconfiguration-35dfde9e2037
    https://hackingthe.cloud/aws/exploitation/cognito_user_self_signup/

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Broken Access Control (BAC)</summary>
  
    - Common Weakness Enumeration:
    CWE-284: Improper Access Control

    - References:
    https://portswigger.net/web-security/access-contro
    https://owasp.org/Top10/A01_2021-Broken_Access_Control/
    https://www.eccouncil.org/cybersecurity-exchange/web-application-hacking/broken-access-control-vulnerability/

    - OWASP Web Top 10:
    A01:Broken Access Control

    - OWASP API Top 10 (2023):
    API1:Broken Object Level Authorization
        
</details>

<details>
  <summary>Broken Link Hijacking</summary>
  
    - Common Weakness Enumeration:
    CWE-610: Externally Controlled Reference to a Resource in Another Sphere

    - References:
    https://www.acunetix.com/vulnerabilities/web/broken-link-hijacking/
    https://www.indusface.com/blog/what-is-broken-link-hijacking/
    https://www.cobalt.io/blog/hunting-for-broken-link-hijacking-blh

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Password Spraying/Brute Forcing</summary>
  
    - Common Weakness Enumeration:
    CWE-307: Improper Restriction of Excessive Authentication Attempts

    - References:
    https://www.kaspersky.com/resource-center/definitions/brute-force-attack
    https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks
    https://sucuri.net/guides/what-is-brute-force-attack/

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Business Logic Errors</summary>
  
    - Common Weakness Enumeration:
    CWE-841: Improper Enforcement of Behavioral Workflow

    - References:
    https://portswigger.net/web-security/logic-flaws
    https://portswigger.net/web-security/logic-flaws/examples
    https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability

    - OWASP Web Top 10:
    A04:Insecure Design

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Clickjacking/UI Reddresing</summary>
  
    - Common Weakness Enumeration:
    CWE-1021: Improper Restriction of Rendered UI Layers or Frames

    - References:
    https://www.acunetix.com/vulnerabilities/web/clickjacking-x-frame-options-header/
    https://portswigger.net/web-security/clickjacking
    https://www.invicti.com/learn/clickjacking/

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Cross Site Request Forgery (CSRF)</summary>
  
    - Common Weakness Enumeration:
    CWE-352: Cross-Site Request Forgery (CSRF)

    - References:
    https://blog.intigriti.com/hackademy/cross-site-request-forgery-csrf/
    https://portswigger.net/web-security/csrf
    https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/cross-site-request-forgery/

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Directory Listing - WordPress Files</summary>
  
    - Common Weakness Enumeration:
    CWE-548: Exposure of Information Through Directory Listing

    - References:
    https://www.wpbeginner.com/wp-tutorials/disable-directory-browsing-wordpress/

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Exposure of Sensitive Information</summary>
  
    - Common Weakness Enumeration:
    CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

    - Description:
    The application does not handle sensitive information correctly, this could lead to exposure of credentials, tokens, and more.
    This is an initial step for any attacker, called information gathering.

    - References:
    https://portswigger.net/web-security/information-disclosure
    https://knowledge-base.secureflag.com/vulnerabilities/sensitive_information_exposure/sensitive_information_disclosure_vulnerability.html
    https://www.invicti.com/blog/web-security/information-disclosure-issues-attacks/

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>GraphQL Alias Overloading Allowed: Potential Denial of Service Vulnerability</summary>
  
    - Common Weakness Enumeration:
    CWE-400: Uncontrolled Resource Consumption

    - Description:
    Your web application is running with GraphQL Alias Overloading enabled, allowing 100+ aliases in a single request.
    GraphQL aliases allow clients to perform the same query multiple times in a single request by assigning a different name to each of them.

    - References:
    https://www.acunetix.com/vulnerabilities/web/graphql-alias-overloading-allowed-potential-denial-of-service-vulnerability/
    https://graphql.org/learn/queries/#aliases
    https://dev.to/ivandotv/preventing-graphql-batching-attacks-56o3

    - OWASP Web Top 10:
    A04:Insecure Design

    - OWASP API Top 10 (2023):
    API10:Unsafe Consumption of APIs
        
</details>

<details>
  <summary>GraphQL Array-based Query Batching Allowed: Potential Batching Attack Vulnerability</summary>
  
    - Common Weakness Enumeration:
    CWE-770: Allocation of Resources Without Limits or Throttling

    - Description:
    Your web application is running with GraphQL Array-based Query Batching enabled, allowing 10+ simultaneous queries in a single request.
    GraphQL Query Batching is a feature that permits multiple queries to be sent to the server in a single request, reducing server processing overhead.

    - References:
    https://www.acunetix.com/vulnerabilities/web/graphql-array-based-query-batching-allowed-potential-batching-attack-vulnerability/
    https://escape.tech/blog/graphql-batch-attacks-cause-dos/
    https://inigo.io/blog/defeating_controls_with_array-based_query_batching/

    - OWASP Web Top 10:
    A04:Insecure Design

    - OWASP API Top 10. (2023):
    API10:Unsafe Consumption of APIs
        
</details>

<details>
  <summary>GraphQL Field Suggestions Enabled</summary>
  
    - Common Weakness Enumeration:
    CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

    - Description:
    GraphQL Field Suggestions is a feature that provides clients with suggested field names when an invalid or non-existent field is queried.

    - References:
    https://www.acunetix.com/vulnerabilities/web/graphql-field-suggestions-enabled/
    https://github.com/apollographql/apollo-server/issues/3919
    https://portswigger.net/kb/issues/00200513_graphql-suggestions-enabled
    https://www.tenable.com/plugins/was/112895

    - OWASP Web Top 10:
    A04:Insecure Design

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>GraphQL Non-JSON Queries/Mutations over GET: Potential CSRF Vulnerability</summary>
  
    - Common Weakness Enumeration:
    CWE-352: Cross-Site Request Forgery (CSRF)

    - Description:
    Your web application's GraphQL implementation accepts non-JSON queries over GET requests, increasing the risk of Cross-Site Request Forgery (CSRF) attacks.

    - References:
    https://www.apollographql.com/docs/router/configuration/csrf/
    https://www.apollographql.com/docs/apollo-server/security/cors
    https://www.acunetix.com/vulnerabilities/web/graphql-non-json-queries-over-get-potential-csrf-vulnerability/
    https://blog.doyensec.com/2021/05/20/graphql-csrf.html

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Guessable/Weak/Low complexity Password Usage</summary>
  
    - Common Weakness Enumeration:
    CWE-1391: Use of Weak Credentials

    - Description:
    The application is using weak credentials that can be easily guessable on brute force or password spraying attack.

    - References:
    https://www.cybersecurity-automation.com/what-are-the-risks-of-weak-passwords/

    - OWASP Web Top 10:
    A04:Insecure Design

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>HTML Injection</summary>
  
    - Common Weakness Enumeration:
    CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)

    - References:
    https://www.acunetix.com/vulnerabilities/web/html-injection/
    https://www.invicti.com/learn/html-injection/
    https://www.softwaretestinghelp.com/html-injection-tutorial/

    - OWASP Web Top 10:
    A03:Injection

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Improper Authorization</summary>
  
    - Common Weakness Enumeration:
    CWE-285: Improper Authorization

    - References:
    https://owasp.org/Top10/TC/A3
    https://www.sans.org/security-awareness-training/cyber-security-topics/improper-authorization-access-control
    https://www.webappsec.org/projects/threat/classes/access_control_flaws.shtml

    - OWASP Web Top 10:
    A07:Identification and Authentication Failures

    - OWASP API Top 10 (2023):
    API3:Broken Object Property Level Authorization
        
</details>

<details>
  <summary>Improper Error Handling</summary>
  
    - Common Weakness Enumeration:
    CWE-209: Generation of Error Message Containing Sensitive Information

    - References:
    https://deviq.com/practices/descriptive-error-messages
    https://owasp.org/www-community/Improper_Error_Handling

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Improper Input Validation</summary>
  
    - Common Weakness Enumeration:
    CWE-20: Improper Input Validation

    - References:
    https://owasp.org/www-community/vulnerabilities/Improper_Data_Validation
    https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Insecure Direct Object Reference (IDOR)</summary>
  
    - Common Weakness Enumeration:
    CWE-639: Authorization Bypass Through User-Controlled Key

    - References:
    https://portswigger.net/web-security/access-control/idor
    https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
    https://www.invicti.com/blog/web-security/insecure-direct-object-reference-vulnerabilities-idor/

    - OWASP Web Top 10:
    A01:Broken Access Control

    - OWASP API Top 10 (2023):
    API1:Broken Object Level Authorization
        
</details>

<details>
  <summary>Insufficient Session Expiration</summary>
  
    - Common Weakness Enumeration:
    CWE-613: Insufficient Session Expiration

    - Description:
    The application permits an attacker to reuse old session credentials or session IDs for authorization.
    One good example, is those applications, where you request for an 'Forgot Password' function, and an link is sent to your mailbox, and that link can be reused many times without any expiration.

    - References:
    https://www.immuniweb.com/vulnerability/insufficient-session-expiration.html
    https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

    - OWASP Web Top 10:
    A04:Insecure Design

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Missing Authentication</summary>
  
    - Common Weakness Enumeration:
    CWE-306: Missing Authentication for Critical Function

    - Description:
    The application does not have any authentication for access some functions.
    It does not require any kind of access, leading to full anonymous access.   

    - References:
    https://auth0.com/docs/get-started/applications/confidential-and-public-applications

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Open Redirection</summary>
  
    - Common Weakness Enumeration:
    CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

    - References:
    https://blog.intigriti.com/hackademy/open-redirect/
    https://learn.snyk.io/lessons/open-redirect/javascript/
    https://portswigger.net/kb/issues/00500100_open-redirection-reflected
    https://www.invicti.com/blog/web-security/open-redirect-vulnerabilities-invicti-pauls-security-weekly/

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Privilege Escalation (Horizontal/Vertical)</summary>
  
    - Common Weakness Enumeration:
    CWE-269: Improper Privilege Management

    - Description:
    The application does not handle well with privileges between users roles.
    Horizontal privilege escalation happens when a user can consume functions of users of the same level, but from different companies/profiles.
    Vertifical privilege escalation happens when an basic user role can use functions of an admin role.

    - References:
    https://www.sans.org/security-awareness-training/vertical-horizontal-privilege-escalation
    https://portswigger.net/web-security/access-control

    - OWASP Web Top 10:
    A01:Broken Access Control

    - OWASP API Top 10 (2023):
    API1:Broken Object Level Authorization
        
</details>

<details>
  <summary>Publicly Available Swagger API Documentation</summary>
  
    - Common Weakness Enumeration:
    CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

    - References:
    https://turingsecure.com/knowledge-base/issues/publicly-available-swagger-api-documentation/
    https://www.thesharpener.net/should-i-use-swagger-in-production/

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Rate Limiting</summary>
  
    - Common Weakness Enumeration:
    CWE-770: Allocation of Resources Without Limits or Throttling

    - References:
    https://www.cloudflare.com/learning/bots/what-is-rate-limiting/
    https://kb.intigriti.com/en/articles/5678905-understanding-rate-limiting
    https://apisecurity.io/encyclopedia/content/owasp/api4-lack-of-resources-and-rate-limiting.htm
    https://www.akana.com/blog/rate-limiting

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API10:Unsafe Consumption of APIs
        
</details>

<details>
  <summary>Reflected/DOM/Self/Stored Cross-site scripting (XSS)</summary>
  
    - Common Weakness Enumeration:
    CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

    - References:
    https://owasp.org/www-community/attacks/xss/
    https://portswigger.net/web-security/cross-site-scripting
    https://www.invicti.com/learn/cross-site-scripting-xss/
    https://blog.intigriti.com/hackademy/cross-site-scripting-xss/

    - OWASP Web Top 10:
    A03:Injection

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Server Side Request Forgery (SSRF)</summary>
  
    - Common Weakness Enumeration:
    CWE-918: Server-Side Request Forgery (SSRF)

    - References:
    https://blog.intigriti.com/hackademy/server-side-request-forgery-ssrf/
    https://portswigger.net/web-security/ssrf
    https://www.invicti.com/learn/server-side-request-forgery-ssrf/
    https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/

    - OWASP Web Top 10:
    A10:Server-Side Request Forgery

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>SQL Injection</summary>
  
    - Common Weakness Enumeration:
    CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

    - References:
    https://portswigger.net/web-security/sql-injection
    https://owasp.org/www-community/attacks/SQL_Injection
    https://www.invicti.com/learn/sql-injection-sqli/

    - OWASP Web Top 10:
    A03:Injection

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Unprotected Credentials</summary>
  
    - Common Weakness Enumeration:
    CWE-522: Insufficiently Protected Credentials

    - Description:
    This case refers to situations where the credentials, keys or tokens are not well protected and encrypted.
    It could lead to possible theft or compromise.
    An example is a attacker get credentials by phishing, social engineering, or exploiting vulnerabilities, and use it to access company systems.
    This usage of valid credentials, could lead to malicious actions, such as stealing data, altering data, or executing unauthorized commands.

    - References:
    N/A

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>User Enumeration</summary>
  
    - Common Weakness Enumeration:
    CWE-203: Observable Discrepancy

    - References:
    https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account
    https://www.virtuesecurity.com/kb/username-enumeration/
    https://www.rapid7.com/blog/post/2017/06/15/about-user-enumeration/

    - OWASP Web Top 10:
    A04:Insecure Design

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

<details>
  <summary>Web Application Firewall (WAF) Bypass</summary>
  
    - Common Weakness Enumeration:
    CWE-693: Protection Mechanism Failure

    - Description:
    The server is protected behind an Web Application Firewall (WAF), but because of historical DNS data, was possible to bypass protections using just the IP Address of the server.

    - References:
    https://www.kitploit.com/2019/01/bypass-firewalls-by-dns-history.html
    https://hacken.io/discover/how-to-bypass-waf-hackenproof-cheat-sheet/

    - OWASP Web Top 10:
    A05:Security Misconfiguration

    - OWASP API Top 10 (2023):
    API8:Security Misconfiguration
        
</details>

