Create Web App

Home > create a resource > marketplace > web app
Publish:code, os will change based on code selected.  App and App service plan and web server are different resources. 

Can enable Continous Deployment through github. Enable public access, net injection (for vnet) off.

Go to resource

Deploy Web App using Vstudio 

Asp.net core template, right click on app name/publish: azure, azure app service, add account, name app resource, click finish, click publish. Deployed to app services. Make changes to indexcshtml then republish. 


MS security baselines for Web App

Search Policy | Assignments

Initiative is a collection or group of related Az policies
The policys scan for something, can take a few hours depending on subscription scope.

Click on Compliance to see the results of this scan.
Click on noncompliant to be taken
Remediation task are not supported by all policy.


Create a Az Function Apps

Enables a function to be triggered by some condition. You are able to set in code and choose an os depending on code and a "backend" vm will be set. 


Configuring a Az Logic App
Creating a resource, it’s a gui canvas for functions. 
When creating, options appear based on the below selection
    • Workflow means logic app
    • Docker container is docker
Choose "disabled" on zone redundancy. 
It can store its running state, storage account
Networking: 
    enable public access - can turn on then you need private endpoints
    Network injection can turn off, can add logging.

Look at app services to get to overview. 
    • Can look at metrics, associated apps
Settings blade:
    • Scale up: increase horsepower 
    • Scale out: more vms under the hood

    Identity blade: 
    • System assigned
    
    • User assigned- to connect to other resources
    
 link a storage account, not by rbac to managed identity but by simply using an access key connection string for the storage account.
Change connection, storage connection string, paste this into the trigger that has to do with blob. 



Can add custom domains, certifcates. 

!!Workflows
    • Think of it like a web app
    • Add from blade on left
        ○ Stateful
            § Standard business transactional data and high reliability.  
        ○ stateless
    • Click Designer

Example:
    • On blade
        ○ Code
        ○ Designer
            § !!Purpose of logic app is Triggers to an action
        ○ Setup
            § Click add a trigger
                □ Look at  allllll of the ways we can
                □ Depending on what you select, the logic app will monitor for that and fire off the action. 
                access key connection string for the storage account.
                Change connection, storage connection string, paste this into the trigger that has to do with blob. 
                
                
            § Logic app can now monitor that storage account blob container looking for new or modified blobs. 
            
            § Click on plus sign, and add an action
                □ 



Az Blueprints
    • 


Artifacts that define the blueprint.
        ○ Resources group
        ○ Rbac role assignment
        ○ Policy assignment
        ○ ARM template / Azure resource manager
            § Find one or more resources and their detailed configuration
            
    So use ARM to deploy into resource group, Use rbac role assignments to allow the management of those resources, and policy to make sure they are compliant. 
     
    
Az blueprint needs to be stored.
    • In a subscription or management group
        ○ management group
            § Part of a heirarchy where you can organize multiple subscriptions in the heirachy together.
                □ To all multiple subs to have access to the print
parameters
    
    
            






Creating an Az Blueprint

Stored in subsrciption
Create resource group
Check, this value should be specified
Assign role based at the resource group level instead of the subscription level, contributor.
Add artifact, could be policy assignment, policy definitions.

Can add arm, like a website. 
Click elipses, "publish blueprint"
Assign Blueprint. 



Using Az App service env (ASE)
App Service view, 
Horsepower- Scale up is increasing performance resource for each vm
Scale out, add in multiple vms. 
In the vnet, the app can talk to multiple resources but not vice versa
Role assignment, 
Config, settings, https, id provider

Configuring Az App server external authentication
Add "identity provider" at creation. 
View App registration
Will require user to consent only 1 time. 


Enabling Az Web App Network Restrictions
App services > networking > inbound traffic-Access Restriction
With public access turned off how do we allow access from vnets
    Create a private endpoint,
    It create a vnic that injects its self into a network
    Add "Private endpoint" - name: webappendpoint
    Create
Look at vnetworks, look at subnet, look at connected devices to see web app. Any services in that vnet can access that web app. 
Think of the endpoint as a jumpbox or proxy. We can access it through the endpoint. 

Working with Message Queues
Scenario: mq in storage account
Mq: way for devs to exchange messages across componets. Code can be dropped in a que and wait until it gets picked up by another software component. 

create a resource, new storage group name" app1queue" 
Open resource
Authentication is by default "Access key" and able to switch to Azure AD user account

-devs use StrAcct access keys, can use that in the mq code.  Or use sas for queue, certain mq libs are needed. 
Set a access policy and role

Working with Web App Deployment Slots


Configuring a Web App Custom Domain Name


Az Content Delivery Networks (CDN)

Enabling a Web app CDN

TEST
