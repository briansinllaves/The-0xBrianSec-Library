
1. With Burp running, investigate the login page and submit an invalid userne and password.
2. In Burp, go to **Proxy > HTTP history** and find the `POST /login` request. Highlight the value of the `userne` parameter in the request and send it to Burp Intruder.
3. In Burp Intruder, go to the **Positions** tab. Notice that the `userne` parameter is automatically set as a payload position. This position is indicated by two `§` symbols, for example: `userne=§invalid-userne§`. Leave the password as any static value for now.
4. Make sure that the **Sniper** attack type is selected.
5. On the **Payloads** tab, make sure that the **Simple list** payload type is selected.
6. Under **Payload settings**, paste the list of candidate usernes. Finally, click **Start attack**. The attack will start in a new window.
7. When the attack is finished, on the **Results** tab, examine the **Length** column. You can click on the column header to sort the results. Notice that one of the entries is longer than the others. Compare the response to this payload with the other responses. Notice that other responses contain the message `Invalid userne`, but this response says `Incorrect password`. Make a note of the userne in the **Payload** column.
8. Close the attack and go back to the **Positions** tab. Click **Clear**, then change the `userne` parameter to the userne you just identified. Add a payload position to the `password` parameter. The result should look something like this:
    
    `userne=identified-user&password=§invalid-password§`
9. On the **Payloads** tab, clear the list of usernes and replace it with the list of candidate passwords. Click **Start attack**.
10. When the attack is finished, look at the **Status** column. Notice that each request received a response with a `200` status code except for one, which got a `302` response. This suggests that the login attempt was successful - make a note of the password in the **Payload** column.
11. Log in using the userne and password that you identified and access the user account page to solve the lab.
    
    #### Note
    
    It's also possible to brute-force the login using a single cluster bomb attack. However, it's generally much more efficient to enumerate a valid userne first if possible.