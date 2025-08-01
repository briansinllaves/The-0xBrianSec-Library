A poisoned web cache can potentially be a devastating means of distributing numerous different attacks, exploiting vulnerabilities such as [XSS](https://portswigger.net/web-security/cross-site-scripting), JavaScript injection, open redirection, and so on.

### Identify and evaluate unkeyed inputs

Any web cache poisoning attack relies on manipulation of unkeyed inputs, such as headers.

You can identify unkeyed inputs manually by adding random inputs to requests and observing whether or not they have an effect on the response

use tools such as Burp Comparer to compare the response with and without the injected input

Param Miner, 
you simply right-click on a request that you want to investigate and click "Guess headers". Param Miner then runs in the background, sending requests containing different inputs from its extensive, built-in list of headers. 

If a request containing one of its injected inputs has an effect on the response, Param Miner logs this in Burp, either in the "Issues" pane

**Caution:** When testing for unkeyed inputs on a live website, there is a risk of inadvertently causing the cache to serve your generated responses to real users. Therefore, it is important to make sure that your requests all have a unique cache key so that they will only be served to you. To do this, you can manually add a cache buster (such as a unique parameter) to the request line each time you make a request. Alternatively, if you are using Param Miner, there are options for automatically adding a cache buster to every request.


### Elicit a harmful response from the back-end server

