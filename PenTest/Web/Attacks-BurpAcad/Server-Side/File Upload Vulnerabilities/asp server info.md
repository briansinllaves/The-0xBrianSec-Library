

similar to `<?php phpinfo(): ?>`
```
<%
Response.Write(Server.HTMLEncode(Request.ServerVariables("ALL_HTTP")))
%>

```

```
<%  
Response.Write("<h1>ASP Info</h1>")  
  
Response.Write("<h2>Server Variables:</h2>")  
For Each key In Request.ServerVariables  
    Response.Write(key & ": " & Request.ServerVariables(key) & "<br>")  
Next  
  
Response.Write("<h2>Server Details:</h2>")  
Response.Write("Server ne: " & Server.Machinene & "<br>")  
Response.Write("Server Software: " & Request.ServerVariables("SERVER_SOFTWARE") & "<br>")  
Response.Write("Server IP Address: " & Request.ServerVariables("LOCAL_ADDR") & "<br>")  
Response.Write("Server Port: " & Request.ServerVariables("SERVER_PORT") & "<br>")  
Response.Write("Server Protocol: " & Request.ServerVariables("SERVER_PROTOCOL") & "<br>")  
  
Response.Write("<h2>ASP Version:</h2>")  
Response.Write("ASP Version: " & ScriptEngineMajorVersion & "." & ScriptEngineMinorVersion & "<br>")  
  
Response.Write("<h2>Request Details:</h2>")  
Response.Write("HTTP Method: " & Request.ServerVariables("REQUEST_METHOD") & "<br>")  
Response.Write("Request URL: " & Request.ServerVariables("URL") & "<br>")  
Response.Write("Request QueryString: " & Request.ServerVariables("QUERY_STRING") & "<br>")  
  
Response.Write("<h2>Request Headers:</h2>")  
For Each header In Request.ServerVariables("ALL_HTTP").Split(vbCrLf)  
    If header.Trim() <> "" Then  
        Dim headerne As String = Left(header, InStr(header, ":") - 1)  
        Dim headerValue As String = Mid(header, InStr(header, ":") + 1)  
        Response.Write(headerne & ": " & headerValue & "<br>")  
    End If  
Next  
  
Response.Write("<h2>Environment Variables:</h2>")  
For Each envVar In Request.ServerVariables("ALL_HTTP").Split(vbCrLf)  
    If envVar.Trim() <> "" Then  
        Dim envVarne As String = Left(envVar, InStr(envVar, "=") - 1)  
        Dim envVarValue As String = Mid(envVar, InStr(envVar, "=") + 1)  
        Response.Write(envVarne & ": " & envVarValue & "<br>")  
    End If  
Next  
%>  

```