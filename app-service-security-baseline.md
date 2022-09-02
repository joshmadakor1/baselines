---
title: Azure security baseline for App Service
description: The App Service security baseline provides procedural guidance and resources for implementing the security recommendations specified in the Azure Security Benchmark.
author: msmbaldwin
ms.service: app-service
ms.topic: conceptual
ms.date: 09/02/2022
ms.author: mbaldwin
ms.custom: subject-security-benchmark

# Important: This content is machine generated; do not modify this topic directly. Contact mbaldwin for more information.

---

# Azure security baseline for App Service

This security baseline applies guidance from the [Azure Security Benchmark version 3.0](/security/benchmark/azure/overview) to App Service. The Azure Security Benchmark provides recommendations on how you can secure your cloud solutions on Azure. The content is grouped by the security controls defined by the Azure Security Benchmark and the related guidance applicable to App Service.

You can monitor this security baseline and its recommendations using Microsoft Defender for Cloud. Azure Policy definitions will be listed in the Regulatory Compliance section of the Microsoft Defender for Cloud dashboard.

When a feature has relevant Azure Policy Definitions, they are listed in this baseline to help you measure compliance to the Azure Security Benchmark controls and recommendations. Some recommendations may require a paid Microsoft Defender plan to enable certain security scenarios.

> [!NOTE]
> **Features** not applicable to App Service have been excluded. To see how App Service completely maps to the Azure Security Benchmark, see the **[full App Service security baseline mapping file](https://github.com/MicrosoftDocs/SecurityBenchmarks/tree/master/Azure%20Offer%20Security%20Baselines/3.0/app-service-azure-security-benchmark-v3-latest-security-baseline.xlsx)**.

## Security profile

The security profile summarizes high-impact behaviors of App Service, which may result in increased security considerations.

| Service Behavior Attribute | Value |
|--|--|
| Product Category | Compute, Web |
| Customer can access HOST / OS | No Access |
| Service can be deployed into customer's virtual network | True |
| Stores customer content at rest | True |

## Network security

*For more information, see the [Azure Security Benchmark: Network security](../security-controls-v3-network-security.md).*

### NS-1: Establish network segmentation boundaries

#### Features

##### Virtual Network Integration

**Description**: Service supports deployment into customer's private Virtual Network (VNet). [Learn more](/azure/virtual-network/virtual-network-for-azure-services#services-that-can-be-deployed-into-a-virtual-network).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Feature notes**: Virtual Network Integration is configured by default when using App Service Environments but must be configured manually when using the public multi-tenant offering.

**Configuration Guidance**: Ensure a stable IP for outbound communications towards internet addresses: You can provide a stable outbound IP by using the Virtual Network integration feature. This allows the receiving party to allow-list based on IP, should that be needed.

When using App Service in the Isolated pricing tier, also called an App Service Environment (ASE), you can deploy directly into a subnet within your Azure Virtual Network. Use network security groups to secure your Azure App Service Environment by blocking inbound and outbound traffic to resources in your virtual network, or to restrict access to apps in an App Service Environment.

In the multi-tenant App Service (an app not in Isolated tier), enable your apps to access resources in or through a Virtual Network with the Virtual Network Integration feature. You can then use network security groups to control outbound traffic from your app. When using Virtual Network Integration, you can enable the 'Route All' configuration to make all outbound traffic subject to network security groups and user-defined routes on the integration subnet. This feature can also be used to block outbound traffic to public addresses from the app. Virtual Network Integration cannot be used to provide inbound access to an app.

For communications towards Azure Services often there's no need to depend on the IP address and mechanics like Service Endpoints should be used instead.

**Reference**: [Integrate your app with an Azure virtual network](/azure/app-service/overview-vnet-integration)

**Guidance notes**: For App Service Environments, by default, network security groups include an implicit deny rule at the lowest priority and requires you to add explicit allow rules. Add allow rules for your network security group based on a least privileged networking approach. The underlying virtual machines that are used to host the App Service Environment are not directly accessible because they are in a Microsoft-managed subscription.

When using Virtual Network Integration feature with virtual networks in the same region, use network security groups and route tables with user-defined routes. User-defined routes can be placed on the integration subnet to send outbound traffic as intended.

##### Network Security Group Support

**Description**: Service network traffic respects Network Security Groups rule assignment on its subnets. [Learn more](/azure/virtual-network/network-security-groups-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | True | Microsoft |

**Feature notes**: Network Security Group support is available for all customers using App Service Environments but is only available on VNet integrated apps for customers using the public multi-tenant offering.

**Configuration Guidance**: No additional configurations are required as this is enabled on a default deployment.

**Reference**: [App Service Environment networking](/azure/app-service/environment/networking)

### NS-2: Secure cloud services with network controls

#### Features

##### Azure Private Link

**Description**: Service native IP filtering capability for filtering network traffic (not to be confused with NSG or Azure Firewall). [Learn more](/azure/private-link/private-link-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use private endpoints for your Azure Web Apps to allow clients located in your private network to securely access the apps over Private Link. The private endpoint uses an IP address from your Azure VNet address space. Network traffic between a client on your private network and the Web App traverses over the VNet and a Private Link on the Microsoft backbone network, eliminating exposure from the public Internet.

**Custom Guidance**: If running containers on App Service which are stored in Azure Container Registry (ACR) ensure those images are pulled over a private network. Do this by configuring a private endpoint on the ACR storing those images in conjunction with setting the "WEBSITE_PULL_IMAGE_OVER_VNET" application setting on your web application.

**Reference**: [Using Private Endpoints for Azure Web App](/azure/app-service/networking/private-endpoint)

**Guidance notes**: Private Endpoint is only used for incoming flows to your Web App. Outgoing flows won't use this Private Endpoint. You can inject outgoing flows to your network in a different subnet through the VNet integration feature.
The use of private endpoints for services on the receiving end of App Service traffic avoids SNAT from happening and provides a stable outbound IP range.

##### Disable Public Network Access

**Description**: Service supports disabling public network access either through using service-level IP ACL filtering rule (not NSG or Azure Firewall) or using a 'Disable Public Network Access' toggle switch. [Learn more](/security/benchmark/azure/security-controls-v3-network-security#ns-2-secure-cloud-services-with-network-controls).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Disable Public Network Access' using either service-level IP ACL filtering rules or private endpoints or by setting the `publicNetworkAccess` property to disabled in ARM.

**Reference**: [Set up Azure App Service access restrictions](/azure/app-service/app-service-ip-restrictions)

### NS-5: Deploy DDOS protection

#### Other guidance for NS-5

Enable DDOS Protection Standard on the virtual network hosting your App Service's Web Application Firewall. Azure provides DDoS Basic protection on its network, which can be improved with intelligent DDoS Standard capabilities which learns about normal traffic patterns and can detect unusual behavior. DDoS Standard applies to a Virtual Network so it must be configured for the network resource in front of the app, such as Application Gateway or an NVA.

### NS-6: Deploy web application firewall

#### Other guidance for NS-6

Avoid WAF being bypassed for your applications. Make sure the WAF cannot be bypassed by locking down access to only the WAF. Use a combination of Access Restrictions, Service Endpoints and Private Endpoints.

Additionally, protect an App Service Environment by routing traffic through a Web Application Firewall (WAF) enabled Azure Application Gateway or Azure Front Door.

For the multi-tenant offering, secure inbound traffic to your app with:

- Access Restrictions: a series of allow or deny rules that control inbound access
- Service Endpoints: can deny inbound traffic from outside of specified virtual networks or subnets
- Private Endpoints: expose your app to your Virtual Network with a private IP address. With the Private Endpoints enabled on your app, it is no longer internet-accessible

Consider implementing an Azure Firewall to centrally create, enforce, and log application and network connectivity policies across your subscriptions and virtual networks. Azure Firewall uses a static public IP address for virtual network resources, which allows outside firewalls to identify traffic that originates from your virtual network.

## Identity management

*For more information, see the [Azure Security Benchmark: Identity management](../security-controls-v3-identity-management.md).*

### IM-1: Use centralized identity and authentication system

#### Features

##### Azure AD Authentication Required for Data Plane Access

**Description**: Service supports using Azure AD authentication for data plane access. [Learn more](/azure/active-directory/authentication/overview-authentication).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: For authenticated web applications, only use well-known established identity providers to authenticate and authorize user access. In case your app should only be accessed by users of your own organization, or otherwise your users are all using Azure Active Directory (Azure AD), configure Azure AD as the default authentication method to control your data plane access.

**Reference**: [Authentication and authorization in Azure App Service and Azure Functions](/azure/app-service/overview-authentication-authorization)

##### Local Authentication Methods for Data Plane Access

**Description**: Local authentications methods supported for data plane access, such as a local username and password. [Learn more](/azure/app-service/overview-authentication-authorization).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Feature notes**: Avoid the usage of local authentication methods or accounts, these should be disabled wherever possible. Instead use Azure AD to authenticate where possible.

**Configuration Guidance**: Restrict the use of local authentication methods for data plane access. Instead, use Azure Active Directory (Azure AD) as the default authentication method to control your data plane access.

**Reference**: [Authentication and authorization in Azure App Service and Azure Functions](/azure/app-service/overview-authentication-authorization)

### IM-3: Manage application identities securely and automatically

#### Features

##### Managed Identities

**Description**: Data plane actions support authentication using managed identities. [Learn more](/azure/active-directory/managed-identities-azure-resources/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use Azure managed identities instead of service principals when possible, which can authenticate to Azure services and resources that support Azure Active Directory (Azure AD) authentication. Managed identity credentials are fully managed, rotated, and protected by the platform, avoiding hard-coded credentials in source code or configuration files.

A common scenario to use a managed identity with App Service is to access other Azure PaaS services such as Azure SQL Database, Azure Storage, or Key Vault.

**Reference**: [How to use managed identities for App Service and Azure Functions](/azure/app-service/overview-managed-identity)

##### Service Principals

**Description**: Data plane supports authentication using service principals. [Learn more](/powershell/azure/create-azure-service-principal-azureps).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Custom Guidance**: Though service principals are supported by the service as a pattern for authentication, we recommend using Managed Identities where possible instead.

### IM-7: Restrict resource access based on conditions

#### Features

##### Conditional Access for Data Plane

**Description**: Data plane access can be controlled using Azure AD Conditional Access Policies. [Learn more](/azure/active-directory/conditional-access/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Define the applicable conditions and criteria for Azure Active Directory (Azure AD) conditional access in the workload. Consider common use cases such as blocking or granting access from specific locations, blocking risky sign-in behavior, or requiring organization-managed devices for specific applications.

### IM-8: Restrict the exposure of credential and secrets

#### Features

##### Service Credential and Secrets Support Integration and Storage in Azure Key Vault

**Description**: Data plane supports native use of Azure Key Vault for credential and secrets store. [Learn more](/azure/key-vault/secrets/about-secrets).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Ensure that app secrets and credentials are stored in secure locations such as Azure Key Vault, instead of embedding them into code or configuration files. Use a managed identity on your app to then access credentials, or secrets stored in Key Vault in a secure fashion.

**Reference**: [Use Key Vault references for App Service and Azure Functions](/azure/app-service/app-service-key-vault-references)

## Privileged access

*For more information, see the [Azure Security Benchmark: Privileged access](../security-controls-v3-privileged-access.md).*

### PA-7: Follow just enough administration (least privilege) principle

#### Features

##### Azure RBAC for Data Plane

**Description**: Azure Role-Based Access Control (Azure RBAC) can be used to managed access to service's data plane actions. [Learn more](/azure/role-based-access-control/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Configuration Guidance**: This feature is not supported to secure this service.

### PA-8: Determine access process for cloud provider support

#### Features

##### Customer Lockbox

**Description**: Customer Lockbox can be used for Microsoft support access. [Learn more](/azure/security/fundamentals/customer-lockbox-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

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

**Feature notes**: Implement Credential Scanner in your build pipeline to identify credentials within code. Credential Scanner will also encourage moving discovered credentials to more secure locations such as Azure Key Vault.

**Configuration Guidance**: This feature is not supported to secure this service.

### DP-2: Monitor anomalies and threats targeting sensitive data

#### Features

##### Data Leakage/Loss Prevention

**Description**: Service supports DLP solution to monitor sensitive data movement (in customer's content). [Learn more](/security/benchmark/azure/security-controls-v3-data-protection#dp-2-monitor-anomalies-and-threats-targeting-sensitive-data).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Feature notes**: While data identification, classification, and loss prevention features are not yet available for App Service, you can reduce the data exfiltration risk from the virtual network by removing all rules where the destination uses a 'tag' for Internet or Azure services.

Microsoft manages the underlying infrastructure for App Service and has implemented strict controls to prevent the loss or exposure of your data.

Use tags to assist in tracking App Service resources that store or process sensitive information.

**Configuration Guidance**: This feature is not supported to secure this service.

### DP-3: Encrypt sensitive data in transit

#### Features

##### Data in Transit Encryption

**Description**: Service supports data in-transit encryption for data plane. [Learn more](/azure/security/fundamentals/double-encryption#data-in-transit).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use and enforce the default minimum version of TLS v1.2, configured in TLS/SSL settings, for encrypting all information in transit. Also ensure that all HTTP connection requests are redirected to HTTPS.

**Reference**: [Add a TLS/SSL certificate in Azure App Service](/azure/app-service/configure-ssl-certificate?tabs=apex%2Cportal)

### DP-4: Enable data at rest encryption by default

#### Features

##### Data at Rest Encryption Using Platform Keys

**Description**: Data at-rest encryption using platform keys is supported, any customer content at rest is encrypted with these Microsoft managed keys. [Learn more](/azure/security/fundamentals/encryption-atrest#encryption-at-rest-in-microsoft-cloud-services).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | True | Microsoft |

**Feature notes**: Web site content in an App Service app, such as files, are stored in Azure Storage, which automatically encrypts the content at rest. Choose to store application secrets in Key Vault and retrieve them at runtime.

Customer supplied secrets are encrypted at rest while stored in App Service configuration databases.

Note that while locally attached disks can be used optionally by websites as temporary storage, (for example, D:\local and %TMP%), they are not encrypted at rest.

**Configuration Guidance**: No additional configurations are required as this is enabled on a default deployment.

### DP-5: Use customer-managed key option in data at rest encryption when required

#### Features

##### Data at Rest Encryption Using CMK

**Description**: Data at-rest encryption using customer-managed keys is supported for customer content stored by the service. [Learn more](/azure/security/fundamentals/encryption-models).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: If required for regulatory compliance, define the use case and service scope where encryption using customer-managed keys are needed. Enable and implement data at rest encryption using customer-managed key for those services.

**Reference**: [Encryption at rest using customer-managed keys](/azure/app-service/configure-encrypt-at-rest-using-cmk)

**Guidance notes**: Web site content in an App Service app, such as files, are stored in Azure Storage, which automatically encrypts the content at rest. Choose to store application secrets in Key Vault and retrieve them at runtime.

Customer supplied secrets are encrypted at rest while stored in App Service configuration databases.

Note that while locally attached disks can be used optionally by websites as temporary storage, (for example, D:\local and %TMP%), they are not encrypted at rest.

### DP-6: Use a secure key management process

#### Features

##### Key Management in Azure Key Vault

**Description**: The service supports Azure Key Vault integration for any customer keys, secrets, or certificates. [Learn more](/azure/key-vault/general/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use Azure Key Vault to create and control the life cycle of your encryption keys, including key generation, distribution, and storage. Rotate and revoke your keys in Azure Key Vault and your service based on a defined schedule or when there is a key retirement or compromise. When there is a need to use customer-managed key (CMK) in the workload, service, or application level, ensure you follow the best practices for key management: Use a key hierarchy to generate a separate data encryption key (DEK) with your key encryption key (KEK) in your key vault. Ensure keys are registered with Azure Key Vault and referenced via key IDs from the service or application. If you need to bring your own key (BYOK) to the service (such as importing HSM-protected keys from your on-premises HSMs into Azure Key Vault), follow recommended guidelines to perform initial key generation and key transfer.

**Reference**: [Use Key Vault references for App Service and Azure Functions](/azure/app-service/app-service-key-vault-references)

### DP-7: Use a secure certificate management process

#### Features

##### Certificate Management in Azure Key Vault

**Description**: The service supports Azure Key Vault integration for any customer certificates. [Learn more](/azure/key-vault/certificates/certificate-scenarios).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: App Service can be configured with SSL/TLS and other certificates, which can be configured directly on App Service or referenced from Key Vault. To ensure central management of all certificates and secrets, store any certificates used by App Service in Key Vault instead of deploying them locally on App Service directly. When this is configured App Service will automatically download the latest certificate from Azure Key Vault. Ensure the certificate generation follows defined standards without using any insecure properties, such as: insufficient key size, overly long validity period, insecure cryptography. Setup automatic rotation of the certificate in Azure Key Vault based on a defined schedule or when there is a certificate expiration.

**Reference**: [Add a TLS/SSL certificate in Azure App Service](/azure/app-service/configure-ssl-certificate)

## Asset management

*For more information, see the [Azure Security Benchmark: Asset management](../security-controls-v3-asset-management.md).*

### AM-2: Use only approved services

#### Features

##### Azure Policy Support

**Description**: Service configurations can be monitored and enforced via Azure Policy. [Learn more](/azure/governance/policy/tutorials/create-and-manage).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use Microsoft Defender for Cloud to configure Azure Policy to audit and enforce configurations of your Azure resources. Use Azure Monitor to create alerts when there is a configuration deviation detected on the resources. Use Azure Policy [deny] and [deploy if not exists] effects to enforce secure configuration across Azure resources.

**Reference**: [Azure Policy Regulatory Compliance controls for Azure App Service](/azure/app-service/security-controls-policy)

**Guidance notes**: Define and implement standard security configurations for your App Service deployed apps with Azure Policy. Use built-in Azure Policy definitions as well as Azure Policy aliases in the "Microsoft.Web" namespace to create custom policies to alert, audit, and enforce system configurations. Develop a process and pipeline for managing policy exceptions.

### AM-4: Limit access to asset management

#### Other guidance for AM-4

Isolate systems that process sensitive information. To do so, use separate App Service Plans or App Service Environments and consider the use of different subscriptions or management groups.

## Logging and threat detection

*For more information, see the [Azure Security Benchmark: Logging and threat detection](../security-controls-v3-logging-threat-detection.md).*

### LT-1: Enable threat detection capabilities

#### Features

##### Microsoft Defender for Service / Product Offering

**Description**: Service has an offering-specific Microsoft Defender solution to monitor and alert on security issues. [Learn more](/azure/security-center/azure-defender).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use Microsoft Defender for App Service to identify attacks targeting applications running over App Service. When you enable Microsoft Defender for App Service, you immediately benefit from the following services offered by this Defender plan:

- Secure: Defender for App Service assesses the resources covered by your App Service plan and generates security recommendations based on its findings. Use the detailed instructions in these recommendations to harden your App Service resources.

- Detect: Defender for App Service detects a multitude of threats to your App Service resources by monitoring the VM instance in which your App Service is running and its management interface, the requests and responses sent to and from your App Service apps, the underlying sandboxes and VMs, and App Service internal logs.

**Reference**: [Protect your web apps and APIs](/azure/defender-for-cloud/defender-for-app-service-introduction)

### LT-4: Enable logging for security investigation

#### Features

##### Azure Resource Logs

**Description**: Service produces resource logs that can provide enhanced service-specific metrics and logging. The customer can configure these resource logs and send them to their own data sink like a storage account or log analytics workspace. [Learn more](/azure/azure-monitor/platform/platform-logs-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Enable resource logs for your web apps on App Service.

**Reference**: [Enable diagnostics logging for apps in Azure App Service](/azure/app-service/troubleshoot-diagnostic-logs)

## Posture and vulnerability management

*For more information, see the [Azure Security Benchmark: Posture and vulnerability management](../security-controls-v3-posture-vulnerability-management.md).*

### PV-2: Audit and enforce secure configurations

#### Other guidance for PV-2

Turn off remote debugging, remote debugging must not be turned on for production workloads as this opens additional ports on the service which increases the attack surface.

### PV-7: Conduct regular red team operations

#### Other guidance for PV-7

Conduct regular penetration test on your web applications following the [penetration testing rules of engagement](https://www.microsoft.com/msrc/pentest-rules-of-engagement).

## Backup and recovery

*For more information, see the [Azure Security Benchmark: Backup and recovery](../security-controls-v3-backup-recovery.md).*

### BR-1: Ensure regular automated backups

#### Features

##### Azure Backup

**Description**: The service can be backed up by the Azure Backup service. [Learn more](/azure/backup/backup-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Where possible, implement stateless application design to simplify recovery and backup scenarios with App Service.

If you really do need to maintain a stateful application, enable the Backup and Restore feature in App Service which lets you easily create app backups manually or on a schedule. You can configure the backups to be retained up to an indefinite amount of time. You can restore the app to a snapshot of a previous state by overwriting the existing app or restoring to another app. Ensure that regular and automated back-ups occur at a frequency as defined by your organizational policies.

**Reference**: [Back up your app in Azure](/azure/app-service/manage-backup)

**Guidance notes**: App Service can back up the following information to an Azure storage account and container, which you have configured your app to use:

- App configuration
- File content
- Database connected to your app

##### Service Native Backup Capability

**Description**: Service supports its own native backup capability (if not using Azure Backup). [Learn more](/security/benchmark/azure/security-controls-v3-backup-recovery#br-1-ensure-regular-automated-backups).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Configuration Guidance**: This feature is not supported to secure this service.

## DevOps security

*For more information, see the [Azure Security Benchmark: DevOps security](../security-controls-v3-devops-security.md).*

### DS-6: Enforce security of workload throughout DevOps lifecycle

#### Other guidance for DS-6

Deploy code to App Service from a controlled and trusted environment, like a well-managed and secured DevOps deployment pipeline. This avoids code that was not version controlled and verified to be deployed from a malicious host.

## Next steps

- See the [Azure Security Benchmark V3 overview](../overview.md)
- Learn more about [Azure security baselines](../security-baselines-overview.md)
