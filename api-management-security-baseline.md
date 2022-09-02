---
title: Azure security baseline for API Management
description: The API Management security baseline provides procedural guidance and resources for implementing the security recommendations specified in the Azure Security Benchmark.
author: msmbaldwin
ms.service: api-management
ms.topic: conceptual
ms.date: 09/02/2022
ms.author: mbaldwin
ms.custom: subject-security-benchmark

# Important: This content is machine generated; do not modify this topic directly. Contact mbaldwin for more information.

---

# Azure security baseline for API Management

This security baseline applies guidance from the [Azure Security Benchmark version 3.0](/security/benchmark/azure/overview) to API Management. The Azure Security Benchmark provides recommendations on how you can secure your cloud solutions on Azure. The content is grouped by the security controls defined by the Azure Security Benchmark and the related guidance applicable to API Management.

You can monitor this security baseline and its recommendations using Microsoft Defender for Cloud. Azure Policy definitions will be listed in the Regulatory Compliance section of the Microsoft Defender for Cloud dashboard.

When a feature has relevant Azure Policy Definitions, they are listed in this baseline to help you measure compliance to the Azure Security Benchmark controls and recommendations. Some recommendations may require a paid Microsoft Defender plan to enable certain security scenarios.

> [!NOTE]
> **Features** not applicable to API Management have been excluded. To see how API Management completely maps to the Azure Security Benchmark, see the **[full API Management security baseline mapping file](https://github.com/MicrosoftDocs/SecurityBenchmarks/tree/master/Azure%20Offer%20Security%20Baselines/3.0/api-management-azure-security-benchmark-v3-latest-security-baseline.xlsx)**.

## Security profile

The security profile summarizes high-impact behaviors of API Management, which may result in increased security considerations.

| Service Behavior Attribute | Value |
|--|--|
| Product Category | Web |
| Customer can access HOST / OS | No Access |
| Service can be deployed into customer's virtual network | True |
| Stores customer content at rest | False |

## Network security

*For more information, see the [Azure Security Benchmark: Network security](../security-controls-v3-network-security.md).*

### NS-1: Establish network segmentation boundaries

#### Features

##### Virtual Network Integration

**Description**: Service supports deployment into customer's private Virtual Network (VNet). [Learn more](/azure/virtual-network/virtual-network-for-azure-services#services-that-can-be-deployed-into-a-virtual-network).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Deploy Azure API Management inside an Azure Virtual Network (VNET), so it can access backend services within the network. The developer portal and API Management gateway can be configured to be accessible either from the Internet (External) or only within the Vnet (Internal).

- External: the API Management gateway and developer portal are accessible from the public internet via an external load balancer. The gateway can access resources within the virtual network.
   - [External Virtual Network Configuration](https://docs.microsoft.com/azure/api-management/api-management-using-with-vnet)
- Internal: the API Management gateway and developer portal are accessible only from within the virtual network via an internal load balancer. The gateway can access resources within the virtual network.
   - [Internal Virtual Network Configuraiton](https://docs.microsoft.com/azure/api-management/api-management-using-with-internal-vnet)

**Reference**: [Use a virtual network with Azure API Management](/azure/api-management/virtual-network-concepts)

##### Network Security Group Support

**Description**: Service network traffic respects Network Security Groups rule assignment on its subnets. [Learn more](/azure/virtual-network/network-security-groups-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Deploy network security groups (NSG) to your API Management subnets to restrict or monitor traffic by port, protocol, source IP address, or destination IP address. Create NSG rules to restrict your service's open ports (such as preventing management ports from being accessed from untrusted networks). Be aware that by default, NSGs deny all inbound traffic but allow traffic from virtual network and Azure Load Balancers.

Caution: When configuring an NSG on the API Management subnet, there are a set of ports that are required to be open. If any of these ports are unavailable, API Management may not operate properly and may become inaccessible.

**Reference**: [Virtual network configuration reference: API Management](/azure/api-management/virtual-network-reference)

**Guidance notes**: [Configure NSG rules for API Management](https://docs.microsoft.com/azure/api-management/api-management-using-with-vnet#configure-nsg-rules)

### NS-2: Secure cloud services with network controls

#### Features

##### Azure Private Link

**Description**: Service native IP filtering capability for filtering network traffic (not to be confused with NSG or Azure Firewall). [Learn more](/azure/private-link/private-link-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: In instances where you are unable to deploy API Management instances into a virtual network, you should instead deploy a private endpoint to establish a private access point for those resources.

**Reference**: [Connect privately to API Management using a private endpoint](/azure/api-management/private-endpoint)

**Guidance notes**: To enable private endpoints, the API Management instance can't already be configured with an external or internal virtual network. A private endpoint connection supports only incoming traffic to the API Management instance.

##### Disable Public Network Access

**Description**: Service supports disabling public network access either through using service-level IP ACL filtering rule (not NSG or Azure Firewall) or using a 'Disable Public Network Access' toggle switch. [Learn more](/security/benchmark/azure/security-controls-v3-network-security#ns-2-secure-cloud-services-with-network-controls).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Disable public network access either using the IP ACL filtering rule on the NSGs assigned to the service's subnets or a toggling switch for public network access.

**Reference**: [Disable Public Network Access](/azure/api-management/private-endpoint#optionally-disable-public-network-access)

**Guidance notes**: API Management supports deployments into a virtual network, as well as locking down non-network-based deployments with a private endpoint and disabling public network access.

### NS-6: Deploy web application firewall

#### Other guidance for NS-6

To protect critical Web/HTTP APIs configure API Management within a Virtual Network (VNET) in internal mode and configure an Azure Application Gateway. Application Gateway is a PaaS service. It acts as a reverse-proxy and provides L7 load balancing, routing, web application firewall (WAF), and other services. [Learn more](https://docs.microsoft.com/azure/api-management/api-management-howto-integrate-internal-vnet-appgateway).

Combining API Management provisioned in an internal VNET with the Application Gateway frontend enables the following scenarios:

- Use a single API Management resource for exposing all APIs to both internal consumers and external consumers.
- Use a single API Management resource for exposing a subset of APIs to external consumers.
- Provide a way of switching access to API Management from the public Internet on and off.

## Identity management

*For more information, see the [Azure Security Benchmark: Identity management](../security-controls-v3-identity-management.md).*

### IM-1: Use centralized identity and authentication system

#### Features

##### Azure AD Authentication Required for Data Plane Access

**Description**: Service supports using Azure AD authentication for data plane access. [Learn more](/azure/active-directory/authentication/overview-authentication).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use Azure Active Directory (Azure AD) as the default authentication method for API Management where possible.

- Configure your Azure API Management Developer Portal to authenticate developer accounts by using Azure AD.
- Configure your Azure API Management instance to protect your APIs by using the OAuth 2.0 protocol with Azure AD.

**Reference**: [Protect an API in Azure API Management using OAuth 2.0 authorization with Azure Active Directory](/azure/api-management/api-management-howto-protect-backend-with-aad)

##### Local Authentication Methods for Data Plane Access

**Description**: Local authentications methods supported for data plane access, such as a local username and password. [Learn more](/azure/app-service/overview-authentication-authorization).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Feature notes**: Avoid the usage of local authentication methods or accounts, these should be disabled wherever possible. Instead use Azure AD to authenticate where possible.

**Configuration Guidance**: Restrict the use of local authentication methods for data plane access, maintain inventory of API Management user accounts and reconcile access as needed. In API Management, developers are the consumers of the APIs that exposed with API Management. By default, newly created developer accounts are Active, and associated with the Developers group. Developer accounts that are in an active state can be used to access all of the APIs for which they have subscriptions.

Also, Azure API Management subscriptions are one means of securing access to APIs and come with a pair of generated subscription keys which support rotation.

Instead of using other auth methods, where possible use Azure Active Directory (Azure AD) as the default authentication method to control your data plane access.

**Reference**: [Authenticate with Basic](/azure/api-management/api-management-authentication-policies#Basic)

### IM-3: Manage application identities securely and automatically

#### Features

##### Managed Identities

**Description**: Data plane actions support authentication using managed identities. [Learn more](/azure/active-directory/managed-identities-azure-resources/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use a Managed Service Identity generated by Azure Active Directory (Azure AD) to allow your API Management instance to easily and securely access other Azure AD-protected resources, such as Azure Key Vault instead of using service principals. Managed identity credentials are fully managed, rotated, and protected by the platform, avoiding hard-coded credentials in source code or configuration files.

**Reference**: [Authenticate with managed identity](/azure/api-management/api-management-authentication-policies#ManagedIdentity)

##### Service Principals

**Description**: Data plane supports authentication using service principals. [Learn more](/powershell/azure/create-azure-service-principal-azureps).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: There is no current Microsoft guidance for this feature configuration. Please review and determine if your organization wants to configure this security feature.

### IM-5: Use single sign-on (SSO) for application access

#### Other guidance for IM-5

Azure API Management can be configured to leverage Azure Active Directory (Azure AD) as an identity provider for authenticating users on the Developer Portal in order to benefit from the SSO capabilities offered by Azure AD. Once configured, new Developer Portal users can choose to follow the out-of-the-box sign-up process by first authenticating through Azure AD and then completing the sign-up process on the portal once authenticated.

Alternatively, the sign-in/sign-up process can be further customized through delegation. Delegation allows you to use your existing website for handling developer sign in/sign up and subscription to products, as opposed to using the built-in functionality in the developer portal. It enables your website to own the user data and perform the validation of these steps in a custom way.

### IM-7: Restrict resource access based on conditions

#### Features

##### Conditional Access for Data Plane

**Description**: Data plane access can be controlled using Azure AD Conditional Access Policies. [Learn more](/azure/active-directory/conditional-access/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Configuration Guidance**: This feature is not supported to secure this service.

### IM-8: Restrict the exposure of credential and secrets

#### Features

##### Service Credential and Secrets Support Integration and Storage in Azure Key Vault

**Description**: Data plane supports native use of Azure Key Vault for credential and secrets store. [Learn more](/azure/key-vault/secrets/about-secrets).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Set up integration of API Management with Azure Key Vault. Ensure that secrets for API Management (Named values) are stored an Azure Key Vault so they can be securely accessed and updated.

**Reference**: [Use named values in Azure API Management policies with Key Vault Integration](/azure/api-management/api-management-howto-properties)

## Privileged access

*For more information, see the [Azure Security Benchmark: Privileged access](../security-controls-v3-privileged-access.md).*

### PA-1: Separate and limit highly privileged/administrative users

#### Features

##### Local Admin Accounts

**Description**: Service has the concept of a local administrative account. [Learn more](/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Feature notes**: Avoid the usage of local authentication methods or accounts, these should be disabled wherever possible. Instead use Azure AD to authenticate where possible.

**Configuration Guidance**: If not required for routine administrative operations, disable or restrict any local admin accounts for only emergency use.

**Reference**: [How to manage user accounts in Azure API Management](/azure/api-management/api-management-howto-create-or-invite-developers)

**Guidance notes**: API Management allows creation of local user account. Instead of creating these local accounts, enable Azure Active Directory (Azure AD) authentication only, and assign permissions to these Azure AD accounts.

### PA-7: Follow just enough administration (least privilege) principle

#### Features

##### Azure RBAC for Data Plane

**Description**: Azure Role-Based Access Control (Azure RBAC) can be used to managed access to service's data plane actions. [Learn more](/azure/role-based-access-control/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use Azure role-based access control (Azure RBAC) for controlling access to Azure API Management. Azure API Management relies on Azure role-based access control to enable fine-grained access management for API Management services and entities (for example, APIs and policies).

**Reference**: [How to use Role-Based Access Control in Azure API Management](/azure/api-management/api-management-role-based-access-control)

### PA-8: Determine access process for cloud provider support

#### Features

##### Customer Lockbox

**Description**: Customer Lockbox can be used for Microsoft support access. [Learn more](/azure/security/fundamentals/customer-lockbox-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Shared |

**Configuration Guidance**: In support scenarios where Microsoft needs to access your data, use Customer Lockbox to review, then approve or reject each of Microsoft's data access requests.

## Data protection

*For more information, see the [Azure Security Benchmark: Data protection](../security-controls-v3-data-protection.md).*

### DP-1: Discover, classify, and label sensitive data

#### Features

##### Sensitive Data Discovery and Classification

**Description**: Tools (such as Azure Purview or Azure Information Protection) can be used for data discovery and classification in the service. [Learn more](/security/benchmark/azure/security-controls-v3-data-protection#dp-1-discover-classify-and-label-sensitive-data).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Configuration Guidance**: This feature is not supported to secure this service.

### DP-2: Monitor anomalies and threats targeting sensitive data

#### Features

##### Data Leakage/Loss Prevention

**Description**: Service supports DLP solution to monitor sensitive data movement (in customer's content). [Learn more](/security/benchmark/azure/security-controls-v3-data-protection#dp-2-monitor-anomalies-and-threats-targeting-sensitive-data).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Configuration Guidance**: This feature is not supported to secure this service.

### DP-3: Encrypt sensitive data in transit

#### Features

##### Data in Transit Encryption

**Description**: Service supports data in-transit encryption for data plane. [Learn more](/azure/security/fundamentals/double-encryption#data-in-transit).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | True | Microsoft |

**Configuration Guidance**: No additional configurations are required as this is enabled on a default deployment.

**Reference**: [Manage protocols and ciphers in Azure API Management](/azure/api-management/api-management-howto-manage-protocols-ciphers)

#### Other guidance for DP-3

Management plane calls are made through Azure Resource Manager over TLS. A valid JSON web token (JWT) is required. Data plane calls can be secured with TLS and one of supported authentication mechanisms (for example, client certificate or JWT).

### DP-6: Use a secure key management process

#### Features

##### Key Management in Azure Key Vault

**Description**: The service supports Azure Key Vault integration for any customer keys, secrets, or certificates. [Learn more](/azure/key-vault/general/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Set up integration of API Management with Azure Key Vault. Ensure that keys used by API Management are stored an Azure Key Vault so they can be securely accessed and updated.

**Reference**: [Prerequisites for key vault integration](/azure/api-management/api-management-howto-properties?tabs=azure-portal#prerequisites-for-key-vault-integration)

### DP-7: Use a secure certificate management process

#### Features

##### Certificate Management in Azure Key Vault

**Description**: The service supports Azure Key Vault integration for any customer certificates. [Learn more](/azure/key-vault/certificates/certificate-scenarios).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Set up integration of API Management with Azure Key Vault. Ensure that secrets for API Management (Named values) are stored an Azure Key Vault so they can be securely accessed and updated.

Use Azure Key Vault to create and control the certificate lifecycle, including creation, importing, rotation, revocation, storage, and purging of the certificate. Ensure the certificate generation follows defined standards without using any insecure properties, such as: insufficient key size, overly long validity period, insecure cryptography. Setup automatic rotation of the certificate in Azure Key Vault and the Azure service (if supported) based on a defined schedule or when there is a certificate expiration. If automatic rotation is not supported in the application, ensure they are still rotated using manual methods in Azure Key Vault and the application.

**Reference**: [Secure backend services using client certificate authentication in Azure API Management](/azure/api-management/api-management-howto-mutual-certificates)

## Asset management

*For more information, see the [Azure Security Benchmark: Asset management](../security-controls-v3-asset-management.md).*

### AM-2: Use only approved services

#### Features

##### Azure Policy Support

**Description**: Service configurations can be monitored and enforced via Azure Policy. [Learn more](/azure/governance/policy/tutorials/create-and-manage).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use built-in Azure Policy to monitor and enforce secure configuration across API Management resources. Use Azure Policy aliases in the "Microsoft.ApiManagement" namespace to create custom Azure Policy definitions where required.

**Reference**: [Azure Policy built-in policy definitions for Azure API Management](/azure/api-management/policy-reference)

## Logging and threat detection

*For more information, see the [Azure Security Benchmark: Logging and threat detection](../security-controls-v3-logging-threat-detection.md).*

### LT-1: Enable threat detection capabilities

#### Features

##### Microsoft Defender for Service / Product Offering

**Description**: Service has an offering-specific Microsoft Defender solution to monitor and alert on security issues. [Learn more](/azure/security-center/azure-defender).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Configuration Guidance**: This feature is not supported to secure this service.

### LT-4: Enable logging for security investigation

#### Features

##### Azure Resource Logs

**Description**: Service produces resource logs that can provide enhanced service-specific metrics and logging. The customer can configure these resource logs and send them to their own data sink like a storage account or log analytics workspace. [Learn more](/azure/azure-monitor/platform/platform-logs-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Enable resource logs for API Management, resource logs provide rich information about operations and errors that are important for auditing and troubleshooting purposes. Categories of resource logs for API Management include:

- GatewayLogs
- WebSocketConnectionLogs

**Reference**: [APIM Resource Logs](/azure/api-management/api-management-howto-use-azure-monitor#resource-logs)

## Backup and recovery

*For more information, see the [Azure Security Benchmark: Backup and recovery](../security-controls-v3-backup-recovery.md).*

### BR-1: Ensure regular automated backups

#### Features

##### Azure Backup

**Description**: The service can be backed up by the Azure Backup service. [Learn more](/azure/backup/backup-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Configuration Guidance**: This feature is not supported to secure this service.

##### Service Native Backup Capability

**Description**: Service supports its own native backup capability (if not using Azure Backup). [Learn more](/security/benchmark/azure/security-controls-v3-backup-recovery#br-1-ensure-regular-automated-backups).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Shared |

**Custom Guidance**: Leverage the backup and restore capabilities in Azure API Management service. When leveraging backup capabilities, Azure API Management writes backups to customer-owned Azure Storage accounts. Backup and restore operations are provided by Azure API Management to perform full system backup and restore.

**Reference**: [How to implement disaster recovery using service backup and restore in Azure API Management](/azure/api-management/api-management-howto-disaster-recovery-backup-restore#calling-the-backup-and-restore-operations)

## Next steps

- See the [Azure Security Benchmark V3 overview](../overview.md)
- Learn more about [Azure security baselines](../security-baselines-overview.md)
