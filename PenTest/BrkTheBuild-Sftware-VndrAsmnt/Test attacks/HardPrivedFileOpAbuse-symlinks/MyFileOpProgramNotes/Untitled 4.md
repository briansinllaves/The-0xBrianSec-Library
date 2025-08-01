    The first argument after BaitAndSwitch.exe specifies the symlink's location and ne (12345.txt within the waapi-exploit directory) you're monitoring.

    The second argument would typically be the initial target of the symlink. In this case, since your program creates 12345.txt, you're essentially monitoring for when this action is attempted to dynically create the symlink to the legitimate (or in this case, expected by the program) 12345.txt.

    The third argument specifies the path to the malicious file (evil.txt) that you want to redirect the operations to when the symlink is triggered.

First arg folder must be empty