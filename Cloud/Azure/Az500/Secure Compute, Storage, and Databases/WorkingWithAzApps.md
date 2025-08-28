# Securing and Working with Azure Apps

## Create Web App

### Initial Deployment

**Navigation:** `Home → Create a Resource → Marketplace → Web App`

**Configuration Options:**
- **Publish:** Code (OS will change based on code selected)
- **Runtime Stack:** Determines available OS options
- **App Service Plan:** Defines compute resources (separate resource from web app)

**Important:** App, App Service Plan, and web server are different resources

**Optional Features:**
- **Continuous Deployment** through GitHub integration
- **Public Access** - Enable internet accessibility
- **VNet Injection** - Off by default (for private network integration)

### Post-Deployment Access

**Navigation:** Go to resource after deployment completes

**Management Options:**
- Monitor application performance
- Configure scaling options
- Set up custom domains and SSL certificates
- Manage deployment slots

---

## Deploy Web App using Visual Studio

### Development Workflow

**Project Setup:**
1. Create **ASP.NET Core template** project
2. **Right-click** on app name → **Publish**
3. Select **Azure** as publish target
4. Choose **Azure App Service**

**Publishing Process:**
1. **Add Account** - Sign in to Azure
2. **Name App Resource** - Define app service name
3. **Click Finish** - Complete configuration
4. **Click Publish** - Deploy to App Service

### Continuous Deployment

**Code Updates:**
1. Make changes to `index.cshtml` or other files
2. **Republish** from Visual Studio
3. Changes automatically deployed to App Service

**Best Practices:**
- Use deployment slots for staging
- Implement CI/CD pipelines for production
- Test changes in non-production environments first

---

## Microsoft Security Baselines for Web App

### Policy Management

**Navigation:** `Search Policy → Assignments`

**Key Concepts:**
- **Initiative** - Collection or group of related Azure policies
- **Policy Scan** - Can take hours depending on subscription scope
- **Compliance Results** - View scan outcomes

### Compliance Monitoring

**Compliance Dashboard:**
1. Click **Compliance** to see scan results
2. Click **Non-compliant** to view specific violations
3. Review available remediation options

**Important:** Remediation tasks are not supported by all policies

**Security Baseline Benefits:**
- Standardized security configurations
- Continuous compliance monitoring
- Automated policy enforcement
- Audit trail for compliance reporting

---

## Create Azure Function Apps

### Overview

Azure Functions enable serverless compute where functions are triggered by specific conditions.

**Key Features:**
- **Event-driven execution** - Functions triggered by conditions
- **Code and OS selection** - Choose runtime and platform
- **Backend VM management** - Azure handles infrastructure
- **Automatic scaling** - Scale based on demand

### Configuration Options

**Runtime Selection:**
- Programming language determines available OS options
- Azure manages underlying compute resources
- Pay-per-execution pricing model

**Trigger Types:**
- HTTP requests
- Timer schedules
- Blob storage events
- Queue messages
- Service Bus events

---

## Configuring Azure Logic App

### Overview

Logic Apps provide GUI-based workflow automation with visual designer interface.

### Initial Setup

**Resource Creation:**
- **Workflow** means Logic App
- **Docker Container** option available for containerized scenarios
- **Zone Redundancy** - Choose "disabled" for cost optimization

**Storage Configuration:**
- Logic App stores running state
- Requires associated storage account
- State persistence for workflow reliability

### Networking Configuration

**Public Access:**
- **Enable Public Access** - Internet accessibility
- Can be disabled to require private endpoints

**Network Injection:**
- **Turn off** for public scenarios
- **Turn on** for VNet integration
- **Logging** - Can be added for monitoring

### App Service Plan Management

**Navigation:** `App Services → Overview`

**Available Options:**
- **Metrics** - Performance monitoring
- **Associated Apps** - Linked applications

**Settings Blade Options:**
- **Scale Up** - Increase horsepower (vertical scaling)
- **Scale Out** - Add more VMs (horizontal scaling)

### Identity Configuration

**System Assigned Identity:**
- Automatically managed by Azure
- Used for resource access authentication

**User Assigned Identity:**
- Manually created and managed
- **Use Case:** Connect to other Azure resources
- Can be shared across multiple resources

### Storage Account Integration

**Connection Methods:**
- **Not by RBAC** to managed identity
- **By access key connection string** for storage account
- **Configuration:** Storage connection string pasted into blob trigger

**Custom Domains and Certificates:**
- Add custom domain names
- Configure SSL/TLS certificates
- Integrate with Azure DNS

---

## Logic App Workflows

### Workflow Types

**Stateful:**
- Standard business transactional data
- High reliability requirements
- State preserved between runs

**Stateless:**
- Lightweight execution
- No state preservation
- Better performance for simple scenarios

### Logic App Designer

**Navigation:** `Logic App → Designer`

**Designer Interface:**
- **Code** - View/edit underlying JSON
- **Designer** - Visual workflow creation
- **Setup** - Configuration options

**Core Concept:** Logic Apps use **Triggers** to initiate **Actions**

### Building Workflows

**Add Trigger:**
1. Click **Add a trigger**
2. Review all available trigger types
3. **Selected trigger determines what Logic App monitors**
4. Configure trigger-specific settings

**Example Storage Trigger:**
- Configure access key connection string
- Paste storage connection string into blob trigger
- Logic App monitors storage account blob container
- Triggers on new or modified blobs

**Add Actions:**
1. Click **plus sign** after trigger
2. **Add an action** - Define what happens when triggered
3. Configure action-specific parameters
4. Chain multiple actions together

---

## Azure Blueprints

### Overview

Blueprints define repeatable sets of Azure resources and configurations for consistent deployments.

### Blueprint Artifacts

**Available Artifact Types:**
- **Resource Groups** - Organizational containers
- **RBAC Role Assignments** - Access control configuration
- **Policy Assignments** - Compliance and governance rules
- **ARM Templates** - Resource deployment definitions

**Integration Strategy:**
- **ARM Templates** deploy resources into resource groups
- **RBAC Role Assignments** allow management of those resources
- **Policies** ensure resources remain compliant

### Blueprint Storage

**Storage Locations:**
- **Subscription** level storage
- **Management Group** level storage

**Management Groups:**
- **Hierarchy** for organizing multiple subscriptions
- **Allows multiple subscriptions** access to blueprint
- **Parameters** can be configured at assignment time

---

## Creating an Azure Blueprint

### Blueprint Configuration

**Storage Location:** Stored in subscription

**Artifact Configuration:**
1. **Create Resource Group** - Check "this value should be specified"
2. **Role Assignment** - Assign at resource group level (not subscription)
3. **Role Type** - Contributor role recommended
4. **Policy Assignment** - Add policy definitions as needed
5. **ARM Template** - Can add website or other resources

### Blueprint Lifecycle

**Publishing:**
1. Click **ellipses** → **Publish Blueprint**
2. Version the blueprint for tracking
3. Add release notes for documentation

**Assignment:**
1. **Assign Blueprint** to target subscription
2. Configure parameters during assignment
3. Monitor assignment progress and compliance

---

## Using Azure App Service Environment (ASE)

### Overview

App Service Environment provides isolated and dedicated hosting for App Service apps.

### Scaling Options

**Scale Up (Vertical Scaling):**
- Increase horsepower/performance resources for each VM
- More CPU, memory, storage per instance
- Higher performance per instance

**Scale Out (Horizontal Scaling):**
- Add multiple VMs to handle increased load
- Distribute traffic across instances
- Better fault tolerance

### Network Integration

**VNet Communication:**
- **App can talk to multiple resources** in VNet
- **Resources cannot initiate communication** back to app
- One-way communication pattern

**Configuration Options:**
- **Role Assignment** - Access control management
- **Config Settings** - Application configuration
- **HTTPS** - SSL/TLS configuration
- **Identity Provider** - Authentication setup

---

## Configuring Azure App Service External Authentication

### Identity Provider Setup

**Configuration Process:**
1. **Add Identity Provider** during app creation
2. **View App Registration** after setup
3. **User Consent** - Required only one time per user

**Authentication Flow:**
- Users authenticate through configured provider
- App receives authentication token
- No password management required by app

**Supported Providers:**
- Azure Active Directory
- Facebook
- Google
- Twitter
- GitHub

---

## Enabling Azure Web App Network Restrictions

### Access Restriction Configuration

**Navigation:** `App Services → Networking → Inbound Traffic → Access Restriction`

### Private Endpoint Setup

**Problem:** With public access turned off, how to allow VNet access?

**Solution:** Create Private Endpoint
1. **Private Endpoint Name:** webappendpoint
2. **Create** private endpoint resource
3. **VNet Integration** - Endpoint injects itself into network

### Network Architecture

**Private Endpoint Function:**
- Acts as **jumpbox or proxy** for web app access
- Creates **vNIC** that injects into subnet
- **Any services in VNet** can access web app through endpoint

**Verification:**
1. Check **VNet → Subnets**
2. View **Connected Devices** to see web app endpoint
3. Test access from resources within VNet

---

## Working with Message Queues

### Overview

Message Queues provide asynchronous communication between application components.

**Use Case:** Developers exchange messages across components - code dropped in queue waits for pickup by another software component

### Storage Account Queue Setup

**Resource Creation:**
1. **Create Resource** → **New Storage Account**
2. **Name:** app1queue
3. **Open Resource** after creation

### Authentication Options

**Default Authentication:** Access Key
**Alternative:** Azure AD user account

### Developer Integration

**Access Methods:**
- **Storage Account Access Keys** - Used in message queue code
- **SAS for Queue** - Requires certain message queue libraries
- **Access Policy and Role** - RBAC-based access

---

## Working with Web App Deployment Slots

### Purpose

Deployment slots enable staging and production environment management within the same App Service.

**Benefits:**
- **Blue-green deployments** - Swap between environments
- **Testing in production-like environment**
- **Zero-downtime deployments**
- **Rollback capability**

### Slot Management

**Slot Configuration:**
- Each slot has independent settings
- Connection strings can be slot-specific
- Environment variables per slot
- Custom domains per slot

**Swap Operations:**
- **Manual swap** - Administrator initiated
- **Auto swap** - Triggered by deployment
- **Swap preview** - Test before final swap

---

## Configuring Web App Custom Domain Name

### Domain Configuration

Custom domains provide branded URLs for web applications instead of default azurewebsites.net URLs.

**Requirements:**
- **Domain ownership verification**
- **DNS configuration** - CNAME or A records
- **SSL certificate** for HTTPS
- **Domain validation** process

### SSL/TLS Configuration

**Certificate Options:**
- **App Service Managed Certificate** - Free, automatically managed
- **Key Vault Certificate** - Customer managed
- **Private Certificate** - Upload custom certificate

---

## Azure Content Delivery Networks (CDN)

### Overview

CDN improves application performance by caching content at edge locations globally.

**Benefits:**
- **Reduced latency** - Content served from nearest location
- **Bandwidth savings** - Origin server load reduction
- **Global availability** - Content distribution worldwide
- **DDoS protection** - Additional security layer

### CDN Integration

**Setup Process:**
1. **Create CDN Profile** - Choose pricing tier
2. **Create CDN Endpoint** - Configure origin server
3. **Configure Caching Rules** - Define cache behavior
4. **Custom Domains** - Add branded URLs

---

## Enabling Web App CDN

### CDN Configuration for Web Apps

**Integration Benefits:**
- **Static content acceleration** - Images, CSS, JavaScript
- **Dynamic content optimization** - API responses
- **SSL termination** - HTTPS at edge locations
- **Custom domains** - Branded CDN URLs

**Configuration Steps:**
1. **Navigate to Web App** → **Networking** → **CDN**
2. **Select CDN Provider** - Azure CDN or third-party
3. **Configure Endpoint** - Origin server settings
4. **Set Caching Rules** - Define what content to cache
5. **Test Performance** - Verify improved load times

---

## Key Takeaways for AZ-500

### Critical Concepts

**App Service Security:**
- Web apps, App Service plans, and web servers are separate resources
- Private endpoints enable VNet access without public internet exposure
- Identity providers simplify authentication without password management
- Network restrictions control inbound traffic access

**Logic Apps:**
- Triggers initiate actions in workflow automation
- System-assigned identities provide secure resource access
- Storage account integration uses access keys, not RBAC
- Stateful vs stateless workflows serve different use cases

**Azure Blueprints:**
- Combine resource groups, RBAC, policies, and ARM templates
- Enable consistent, repeatable deployments
- Can be stored at subscription or management group level
- Parameters allow customization during assignment

**Deployment and Scaling:**
- Scale up increases VM performance (vertical scaling)
- Scale out adds more VMs (horizontal scaling)
- Deployment slots enable staging and blue-green deployments
- CDN improves global performance through edge caching

**Network Security:**
- Access restrictions control inbound traffic
- Private endpoints provide secure VNet integration
- Message queues enable asynchronous component communication
- Custom domains require DNS configuration and SSL certificates

**Best Practices:**
- Use managed identities over access keys when possible
- Implement private endpoints for sensitive applications
- Configure deployment slots for production workloads
- Enable CDN for globally distributed applications
- Apply security baselines through Azure Policy