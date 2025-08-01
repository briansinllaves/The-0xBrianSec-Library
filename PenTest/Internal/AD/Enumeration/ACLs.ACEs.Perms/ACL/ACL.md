The problem on answering the question of "What can user X do" is that in AD ACLs are applied on the object itself

\your user has several ACLs on itself that describe what objects have access to you and how

Not vice versa

So to know where some object has access to, would require you to enumerate ACLs for every object in ACL and see if your SID is there or not

Or SID of a group where you belong to




