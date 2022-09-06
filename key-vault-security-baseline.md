---
title: Azure security baseline for Key Vault
description: The Key Vault security baseline provides procedural guidance and resources for implementing the security recommendations specified in the Azure Security Benchmark.
author: msmbaldwin
ms.service: key-vault
ms.topic: conceptual
ms.date: 09/03/2022
ms.author: mbaldwin
ms.custom: subject-security-benchmark

# Important: This content is machine generated; do not modify this topic directly. Contact mbaldwin for more information.

---

# Azure security baseline for Key Vault

This security baseline applies guidance from the [Azure Security Benchmark version 3.0](/security/benchmark/azure/overview) to Key Vault. The Azure Security Benchmark provides recommendations on how you can secure your cloud solutions on Azure. The content is grouped by the security controls defined by the Azure Security Benchmark and the related guidance applicable to Key Vault.

You can monitor this security baseline and its recommendations using Microsoft Defender for Cloud. Azure Policy definitions will be listed in the Regulatory Compliance section of the Microsoft Defender for Cloud dashboard.

When a feature has relevant Azure Policy Definitions, they are listed in this baseline to help you measure compliance to the Azure Security Benchmark controls and recommendations. Some recommendations may require a paid Microsoft Defender plan to enable certain security scenarios.

> [!NOTE]
> **Features** not applicable to Key Vault have been excluded. To see how Key Vault completely maps to the Azure Security Benchmark, see the **[full Key Vault security baseline mapping file](https://github.com/MicrosoftDocs/SecurityBenchmarks/tree/master/Azure%20Offer%20Security%20Baselines/3.0/key-vault-azure-security-benchmark-v3-latest-security-baseline.xlsx)**.

## Security profile

The security profile summarizes high-impact behaviors of Key Vault, which may result in increased security considerations.

| Service Behavior Attribute | Value |
|--|--|
| Product Category | Security |
| Customer can access HOST / OS | No Access |
| Service can be deployed into customer's virtual network | False |
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

**Configuration Guidance**: Azure Key Vault supports virtual network service endpoints which allows you to restrict the key vault access to a specified virtual network.

**Reference**: [Azure Key Vault Network Security](/azure/key-vault/general/network-security)

##### Network Security Group Support

**Description**: Service network traffic respects Network Security Groups rule assignment on its subnets. [Learn more](/azure/virtual-network/network-security-groups-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use network security groups (NSG) to restrict or monitor traffic by port, protocol, source IP address, or destination IP address. Create NSG rules to restrict your service's open ports (such as preventing management ports from being accessed from untrusted networks). Be aware that by default, NSGs deny all inbound traffic but allow traffic from virtual network and Azure Load Balancers.

### NS-2: Secure cloud services with network controls

#### Features

##### Azure Private Link

**Description**: Service native IP filtering capability for filtering network traffic (not to be confused with NSG or Azure Firewall). [Learn more](/azure/private-link/private-link-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Deploy private endpoints for Azure Key Vault to establish a private access point for the resources.

**Reference**: [Azure Key Vault Private Link](/azure/key-vault/general/private-link-service?tabs=portal)

##### Disable Public Network Access

**Description**: Service supports disabling public network access either through using service-level IP ACL filtering rule (not NSG or Azure Firewall) or using a 'Disable Public Network Access' toggle switch. [Learn more](/security/benchmark/azure/security-controls-v3-network-security#ns-2-secure-cloud-services-with-network-controls).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Disable public network access using the Azure Key Vault firewall IP filtering rules.

**Reference**: [Azure Key Vault network security](/azure/key-vault/general/how-to-azure-key-vault-network-security?tabs=azure-portal)

## Identity management

*For more information, see the [Azure Security Benchmark: Identity management](../security-controls-v3-identity-management.md).*

### IM-1: Use centralized identity and authentication system

#### Features

##### Azure AD Authentication Required for Data Plane Access

**Description**: Service supports using Azure AD authentication for data plane access. [Learn more](/azure/active-directory/authentication/overview-authentication).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | True | Microsoft |

**Configuration Guidance**: No additional configurations are required as this is enabled on a default deployment.

**Reference**: [Azure Key Vault authentication](/azure/key-vault/general/authentication)

##### Local Authentication Methods for Data Plane Access

**Description**: Local authentications methods supported for data plane access, such as a local username and password. [Learn more](/azure/app-service/overview-authentication-authorization).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Configuration Guidance**: This feature is not supported to secure this service.

### IM-3: Manage application identities securely and automatically

#### Features

##### Managed Identities

**Description**: Data plane actions support authentication using managed identities. [Learn more](/azure/active-directory/managed-identities-azure-resources/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use Azure managed identities instead of service principals when possible, which can authenticate to Azure services and resources that support Azure Active Directory (Azure AD) authentication. Managed identity credentials are fully managed, rotated, and protected by the platform, avoiding hard-coded credentials in source code or configuration files.

**Reference**: [Azure Key Vault authentication](/azure/key-vault/general/authentication)

##### Service Principals

**Description**: Data plane supports authentication using service principals. [Learn more](/powershell/azure/create-azure-service-principal-azureps).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Custom Guidance**: It is recommended to use managed identities instead of service principals. When service principals have to be used, limit the usage to use case scenarios where non-user-based access is required and managed identities are not supported, such as automation flows or 3rd party system integrations.

**Reference**: [Azure Key Vault authentication](/azure/key-vault/general/authentication#security-principal-registration)

### IM-7: Restrict resource access based on conditions

#### Features

##### Conditional Access for Data Plane

**Description**: Data plane access can be controlled using Azure AD Conditional Access Policies. [Learn more](/azure/active-directory/conditional-access/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Define the applicable conditions and criteria for Azure Active Directory (Azure AD) conditional access in the workload. Consider common use cases such as blocking or granting access from specific locations, blocking risky sign-in behavior, or requiring organization-managed devices for specific applications.

**Reference**: [Azure Key Vault conditional access](/azure/key-vault/general/security-features#conditional-access)

### IM-8: Restrict the exposure of credential and secrets

#### Features

##### Service Credential and Secrets Support Integration and Storage in Azure Key Vault

**Description**: Data plane supports native use of Azure Key Vault for credential and secrets store. [Learn more](/azure/key-vault/secrets/about-secrets).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Ensure that secrets and credentials are stored in secure locations such as Azure Key Vault, instead of embedding them into code or configuration files.

**Reference**: [About Azure Key Vault secrets](/azure/key-vault/secrets/about-secrets)

## Privileged access

*For more information, see the [Azure Security Benchmark: Privileged access](../security-controls-v3-privileged-access.md).*

### PA-1: Separate and limit highly privileged/administrative users

#### Features

##### Local Admin Accounts

**Description**: Service has the concept of a local administrative account. [Learn more](/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Configuration Guidance**: This feature is not supported to secure this service.

### PA-7: Follow just enough administration (least privilege) principle

#### Features

##### Azure RBAC for Data Plane

**Description**: Azure Role-Based Access Control (Azure RBAC) can be used to managed access to service's data plane actions. [Learn more](/azure/role-based-access-control/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use Azure role-based access control (Azure RBAC) to manage Azure resource access through built-in role assignments. Azure RBAC roles can be assigned to users, groups, service principals, and managed identities.

**Reference**: [Azure Key Vault RBAC support](/azure/key-vault/general/rbac-guide?tabs=azure-cli)

## Data protection

*For more information, see the [Azure Security Benchmark: Data protection](../security-controls-v3-data-protection.md).*

### DP-3: Encrypt sensitive data in transit

#### Features

##### Data in Transit Encryption

**Description**: Service supports data in-transit encryption for data plane. [Learn more](/azure/security/fundamentals/double-encryption#data-in-transit).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | True | Microsoft |

**Configuration Guidance**: No additional configurations are required as this is enabled on a default deployment.

**Custom Guidance**: No Additional configurations are required as this is managed by Azure Platform

**Reference**: [Azure Key Vault security features](/azure/key-vault/general/security-features#tls-and-https)

### DP-4: Enable data at rest encryption by default

#### Features

##### Data at Rest Encryption Using Platform Keys

**Description**: Data at-rest encryption using platform keys is supported, any customer content at rest is encrypted with these Microsoft managed keys. [Learn more](/azure/security/fundamentals/encryption-atrest#encryption-at-rest-in-microsoft-cloud-services).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | True | Microsoft |

**Configuration Guidance**: No additional configurations are required as this is enabled on a default deployment.

**Reference**: [Azure Key Vault secure store of secrets and keys](/azure/key-vault/general/overview#securely-store-secrets-and-keys)

### DP-5: Use customer-managed key option in data at rest encryption when required

#### Features

##### Data at Rest Encryption Using CMK

**Description**: Data at-rest encryption using customer-managed keys is supported for customer content stored by the service. [Learn more](/azure/security/fundamentals/encryption-models).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Azure Key Vault is where you store your keys for customer-managed key (CMK) encryption. You have the option to use either software-protected keys or HSM (hardware security module)-protected keys for your CMK solution.

**Reference**: [Azure Key Vault secure store of secrets and keys](/azure/key-vault/general/overview#securely-store-secrets-and-keys)

**Guidance notes**: For customer-managed key and HSM details, please refer to: https://techcommunity.microsoft.com/t5/azure-confidential-computing/azure-key-vault-managed-hsm-control-your-data-in-the-cloud/ba-p/3359310

### DP-6: Use a secure key management process

#### Features

##### Key Management in Azure Key Vault

**Description**: The service supports Azure Key Vault integration for any customer keys, secrets, or certificates. [Learn more](/azure/key-vault/general/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Follow the Azure Key Vault best practices to securely manage your key lifecycle in key vault. This includes the key generation, distribution, storage, rotation, and revocation.

**Reference**: [Azure Key Vault key management](/azure/key-vault/keys/about-keys-details#key-access-control)

### DP-7: Use a secure certificate management process

#### Features

##### Certificate Management in Azure Key Vault

**Description**: The service supports Azure Key Vault integration for any customer certificates. [Learn more](/azure/key-vault/certificates/certificate-scenarios).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Follow the Azure Key Vault best practice to securely manage your certificate lifecycle in the key vault. This includes the key creation/import, rotation, revocation, storage, and purge of the certificate.

**Reference**: [Azure Key Vault certificate management](/azure/key-vault/certificates/create-certificate-scenarios)

## Asset management

*For more information, see the [Azure Security Benchmark: Asset management](../security-controls-v3-asset-management.md).*

### AM-2: Use only approved services

#### Features

##### Azure Policy Support

**Description**: Service configurations can be monitored and enforced via Azure Policy. [Learn more](/azure/governance/policy/tutorials/create-and-manage).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Use Microsoft Defender for Cloud to configure Azure Policy to audit and enforce configurations of your Azure Key Vault. Use Azure Monitor to create alerts when there is a configuration deviation detected on the resources. Use Azure Policy [deny] and [deploy if not exists] effects to enforce secure configuration across Azure resources.

**Reference**: [Azure Key Vault policy](/azure/key-vault/policy-reference)

## Logging and threat detection

*For more information, see the [Azure Security Benchmark: Logging and threat detection](../security-controls-v3-logging-threat-detection.md).*

### LT-1: Enable threat detection capabilities

#### Features

##### Microsoft Defender for Service / Product Offering

**Description**: Service has an offering-specific Microsoft Defender solution to monitor and alert on security issues. [Learn more](/azure/security-center/azure-defender).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Enable Microsoft Defender for Key Vault, when you get an alert from Microsoft Defender for Key Vault, investigate and respond to the alert.

**Reference**: [Microsoft Defender for Azure Key Vault](/azure/defender-for-cloud/defender-for-key-vault-introduction)

### LT-4: Enable logging for security investigation

#### Features

##### Azure Resource Logs

**Description**: Service produces resource logs that can provide enhanced service-specific metrics and logging. The customer can configure these resource logs and send them to their own data sink like a storage account or log analytics workspace. [Learn more](/azure/azure-monitor/platform/platform-logs-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Enable resource logs for your key vault. Resource logs for Azure Key Vault can log key operation activities such as key creation, retrieve, and deletion.

**Reference**: [Azure Key Vault logging](/azure/key-vault/general/logging?tabs=Vault)

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
| True | False | Customer |

**Custom Guidance**: Use Azure Key Vault native backup feature to backup 
 your secrets, keys, and certificates and ensure the service is recoverable using the backup data.

**Reference**: [Azure Key Vault backup](/azure/key-vault/general/backup?tabs=azure-cli)

## Next steps

- See the [Azure Security Benchmark V3 overview](../overview.md)
- Learn more about [Azure security baselines](../security-baselines-overview.md)
