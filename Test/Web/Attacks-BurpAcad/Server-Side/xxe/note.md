

XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.

In some situations, an attacker can escalate an XXE attack to compromise the underlying server or other back-end infrastructure, by leveraging the XXE vulnerability to perform [server-side request forgery](https://portswigger.net/web-security/ssrf) (SSRF) attacks

 There are various types of XXE attacks:

    Exploiting XXE 
    to retrieve files 
	    where an external entity is defined containing the contents of a file, and returned in the application's response.
	
	to perform SSRF attacks
		where an external entity is defined based on a URL to a back-end system.
    
Exploiting blind XXE 

exfiltrate data out-of-band
	where sensitive data is transmitted from the application server to a system that the attacker controls.
   
to retrieve data via error message
	where the attacker can trigger a parsing error message containing sensitive data.
