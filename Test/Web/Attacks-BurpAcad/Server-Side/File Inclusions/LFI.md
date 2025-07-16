1. **ASP.NET**:
   - Example vulnerable code: `Server.Execute("page=../../../../../ETC/PASSWD")`

2. **Java**:
   - Example vulnerable code:
     ```java
     RequestDispatcher rd = request.getRequestDispatcher("page=../../../../../ETC/PASSWD"); 
     rd.include(request, response);
     ```

3. **Node.js**:
   - Example vulnerable code:
     ```javascript
     require("../../../../../ETC/PASSWD");
     
     const fs = require('fs');
     fs.readFile("../../../../../ETC/PASSWD", (err, data) => {
       if (err) throw err;
       console.log(data);
     });
     ```

4. **Python**:
   - Example vulnerable code:
     ```python
     with open("../../../../../ETC/PASSWD", 'r') as file:
         data = file.read()
     ```

5. **Ruby on Rails**:
   - Example vulnerable code:
     ```ruby
     render file: "../../../../../ETC/PASSWD"
     ```

