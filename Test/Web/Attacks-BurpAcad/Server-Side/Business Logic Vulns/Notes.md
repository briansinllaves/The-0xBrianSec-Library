https://portswigger.net/web-security/logic-flaws

Flaws and bugs in how an application processes user requests. These are typically caused by an attacker interacting with the application in a way the developers did not anticipate.

## Examples

### Excessive trust in client-side controls

Assuming that requests will only come through the user interface and be subjected to client-side validation. Easily bypassed by tools like Burp Suite.

go to "Proxy" > "HTTP history" and study the order process. Notice that when you add an item to your cart, the corresponding request contains a price parameter.

Send the POST /cart request to Burp Repeater.

In Burp Repeater, change the price to an arbitrary integer and send the request and show in browser. Refresh the cart and confirm that the price has changed based on your input.

### Failing to handle unconventional input

Bugs triggered by receiving user input that is not of the expected type or within the expected range (e.g. a negative number when only positive values are expected). This must be caught with input and business logic validation.

a negative number when only positive values are expected

### Making flawed assumptions about user behavior

Assuming that users will interact predictably. This can include:

- Not following an expected workflow sequence;

- Not providing all required input; and

- Not remaining trustworthy after initial authentication.

Attempt to bypass sections of workflows (skip ahead to the end).

### Providing an encryption oracle

Occurs when user provided input is then returned as cipher text to the user. This can allow the attacker to determine the encryption algorithm and key used by the application.

Occurs when user provided input is then returned as cipher text to the user

### Insecure Direct Object Reference (IDOR)

is a vulnerability that arises when attackers can access or modify objects by manipulating identifiers used in a web application's URLs or parameters. It occurs due to missing access control checks, which fail to verify whether a user should be allowed to access specific data.

Look for other relevant and relatible objects/data that can you try to access your not expected or authorized to do

### Users won't always supply mandatory input

 try removing each parameter in turn and observing what effect this has on the response. You should make sure to:

- Only remove one parameter at a time to ensure all relevant code paths are reached.

- Try deleting the ne of the parameter as well as the value. The server will typically handle both cases differently.

- Follow multi-stage processes through to completion. Sometimes tampering with a parameter in one step will have an effect on another step further along in the workflow.

This applies to both URL and `POST` parameters, but don't forget to check the cookies too. This simple process can reveal some bizarre application behavior that may be exploitable.


## Domain-specific flaws

pay particular attention to any situation where prices or other sensitive values are adjusted based on criteria determined by user actions. 

Try to understand what algorithms the application uses to make these adjustments and at what point these adjustments are made. 

This often involves manipulating the application so that it is in a state where the applied adjustments do not correspond to the original criteria intended by the developers.

# Inconsistent security controls

try to access resource with an arbitrary email in the request

# Flawed enforcement of business rules

1. make adjustments in the body that may deter from intended action of user, like entering in discounts multiple times. 
2. Try applying the codes more than once. Notice that if you enter the same code twice in a row, it is rejected because the coupon has already been applied. However, if you alternate between the two codes, you can bypass this control.
3. 

## Tips

- Look for all requests that submit input to the server and check if there is adequate server-side validation.

- Submit input that satisfies validation, but is outside of expected ranges (e.g. negative numbers in a scenario where they do not make sense).

- Attempt to bypass sections of workflows (skip ahead to the end).



## Prevent

1. Make sure all developers and testers understand the application logic.
2. Validate all user inputs.
3. Write clear, simple code that is easy to understand and test.
4. Break complex logic into smaller, simpler functions and ensure each function is thoroughly tested.



