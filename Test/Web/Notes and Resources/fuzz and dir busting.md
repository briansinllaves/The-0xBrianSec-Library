
Make a list of all things to fuzz
Discovery/Web-Content/Common-PHP-Filenes.txt
CommonBackdoors-PHP.fuzz.txt
Discovery/Web-Content/PHP.fuzz.txt
Discovery/Web-Content/swagger.txt      for swagger api stuff
Discovery/Web-Content/nginx.txt
Discovery/Web-Content/IIS.fuzz.txt
Discovery/Web-Content/apache.txt
Discovery/Web-Content/big.txt
  
./ffuf -u http://exp1.ABCD.com/FUZZ -v -c -w /home/brian/seclists/Discovery/Web-Content/big.txt -o /home/brian/fuzz/th-big -of html
 
./ffuf -u https://secexa.gpgw.ABCD.com/FUZZ -v -c -w /home/brian/seclists/Discovery/Web-Content/big.txt -o /home/brian/fuzz/ms-big -of html

cd /home/tools/ffuf/ 
cd /home/brian/fuzz
if the list is copy-pasted into your terminal or uploaded via scp, dos2unix ftps.txt should get rid of any issues and extraneous chars that don't translate properly. I wouldn't do that conversion explicitly with iconv because it can make other issues occur if the characters weren't fully in utf-16 in the first place. dos2unix will fix and remove them instead of translating bad chars.
always do a manual inspection after the fact in a console text editor to see if anything was missed though
scp -r Proxy-1:/home/brian/fuzz/ /home/kali/Desktop/

301 Moved Permanently
	The URL of the requested resource has been changed permanently. The new URL is given in the response.
401 Unauthorized
	Although the HTTP standard specifies "unauthorized", semantically this response means "unauthenticated". That is, the client must authenticate itself to get the requested response.
500 Internal Server Error
	The server has encountered a situation it does not know how to handle.
403 Forbidden
The client does not have access rights to the content; that is, it is unauthorized, so the server is refusing to give the requested resource. Unlike 401 Unauthorized, the client's identity is known to the server.