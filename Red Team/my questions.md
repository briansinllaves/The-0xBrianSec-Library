
for webshells, implement ip block and require certian items in request headers. 

we've also got automation to rotate the IPs/domains daily if we think blue are onto us - it'll change the external IPs of all the boxes without rebuilding

we use a NAT gateway so our traffic comes out of 16 random addresses that can be auto-rotated

done too much stuff from one IP we'll rotate it so that if they haven't seen us it's harder to pivot detections on that one IP

