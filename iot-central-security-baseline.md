---
title: Azure security baseline for IoT Central
description: The IoT Central security baseline provides procedural guidance and resources for implementing the security recommendations specified in the Azure Security Benchmark.
author: msmbaldwin
ms.service: iot-central
ms.topic: conceptual
ms.date: 09/03/2022
ms.author: mbaldwin
ms.custom: subject-security-benchmark

# Important: This content is machine generated; do not modify this topic directly. Contact mbaldwin for more information.

---

# Azure security baseline for IoT Central

This security baseline applies guidance from the [Azure Security Benchmark version 3.0](/security/benchmark/azure/overview) to IoT Central. The Azure Security Benchmark provides recommendations on how you can secure your cloud solutions on Azure. The content is grouped by the security controls defined by the Azure Security Benchmark and the related guidance applicable to IoT Central.

You can monitor this security baseline and its recommendations using Microsoft Defender for Cloud. Azure Policy definitions will be listed in the Regulatory Compliance section of the Microsoft Defender for Cloud dashboard.

When a feature has relevant Azure Policy Definitions, they are listed in this baseline to help you measure compliance to the Azure Security Benchmark controls and recommendations. Some recommendations may require a paid Microsoft Defender plan to enable certain security scenarios.

> [!NOTE]
> **Features** not applicable to IoT Central have been excluded. To see how IoT Central completely maps to the Azure Security Benchmark, see the **[full IoT Central security baseline mapping file](https://github.com/MicrosoftDocs/SecurityBenchmarks/tree/master/Azure%20Offer%20Security%20Baselines/3.0/iot-central-azure-security-benchmark-v3-latest-security-baseline.xlsx)**.

## Security profile

The security profile summarizes high-impact behaviors of IoT Central, which may result in increased security considerations.

| Service Behavior Attribute | Value |
|--|--|
| Product Category | IoT |
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
| False | Not Applicable | Not Applicable |

**Feature notes**: IoT Central doesn't support deploying directly into a virtual network. 

To secure IoT Central to a private networking environment, use Azure Private Link.

**Configuration Guidance**: This feature is not supported to secure this service.

### NS-2: Secure cloud services with network controls

#### Features

##### Azure Private Link

**Description**: Service native IP filtering capability for filtering network traffic (not to be confused with NSG or Azure Firewall). [Learn more](/azure/private-link/private-link-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Feature notes**: IoT Central supports private endpoints for enable secure and private connectivity for IoT devices to the cloud.

The private connectivity is enabled for device connections and requires users to update the device's DPS endpoint to enable traffic via private endpoint. Learn more here: https://docs.microsoft.com/azure/iot-central/core/howto-create-private-endpoint#limitations

**Configuration Guidance**: Connect your devices to your IoT Central application by using a private endpoint in an Azure Virtual Network.
Private endpoints use private IP addresses from a virtual network address space to connect your devices privately to your IoT Central application.

**Reference**: [Create and configure a private endpoint for IoT Central](/azure/iot-central/core/howto-create-private-endpoint)

##### Disable Public Network Access

**Description**: Service supports disabling public network access either through using service-level IP ACL filtering rule (not NSG or Azure Firewall) or using a 'Disable Public Network Access' toggle switch. [Learn more](/security/benchmark/azure/security-controls-v3-network-security#ns-2-secure-cloud-services-with-network-controls).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Feature notes**: IoT Central supports disabling public access for device connectivity so that all device traffic can only be reachable via a private endpoint or via specified IP rules.

Learn more about it here: https://docs.microsoft.com/azure/iot-central/core/howto-create-private-endpoint#restrict-public-access

IoT Central also supports Azure Policy to enforce this setting. Learn more about it here: https://docs.microsoft.com/azure/governance/policy/samples/built-in-policies#internet-of-things


Currently, private connectivity is only enabled for device connections to the underlying IoT hubs and DPS in the IoT Central application. The IoT Central web UI and APIs continue to work through their public endpoints.

**Configuration Guidance**: Turn off access from public endpoints to restrict public access for your devices to IoT Central. After you turn off public access, devices can't connect to IoT Central from public networks and must use a private endpoint.

**Reference**: [Restrict public access for devices connecting to Azure IoT Central](/azure/iot-central/core/howto-create-private-endpoint#restrict-public-access)

## Identity management

*For more information, see the [Azure Security Benchmark: Identity management](../security-controls-v3-identity-management.md).*

### IM-1: Use centralized identity and authentication system

#### Features

##### Azure AD Authentication Required for Data Plane Access

**Description**: Service supports using Azure AD authentication for data plane access. [Learn more](/azure/active-directory/authentication/overview-authentication).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Feature notes**: Azure AD identities are supported for all data plane access in IoT Central.

AD users can be added to IoT Central applications for access via portal and the associated AAD bearer tokens can be used to authenticate with REST API.

AD service principals can also be added to IoT Central's data plane access for the authorization required for REST API calls.

**Configuration Guidance**: IoT Central supports two ways for authorizing REST API Calls
1) Azure AD bearer token - A bearer token is associated with an Azure Active Directory user account or service principal. The token grants the caller the same permissions the user or service principal has in the IoT Central application.
2) API token - create a specific API token in the IoT Central application and associate with a role.

Use a bearer token associated with your user account while you're developing and testing automation and scripts that use the REST API. Use a bearer token that's associated with a service principal for production automation and scripts. Use a bearer token in preference to an API token to reduce the risk of leaks and problems when tokens expire.

**Reference**: [Authorize REST API in Azure IoT Central](/azure/iot-central/core/howto-authorize-rest-api)

##### Local Authentication Methods for Data Plane Access

**Description**: Local authentications methods supported for data plane access, such as a local username and password. [Learn more](/azure/app-service/overview-authentication-authorization).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Feature notes**: IoT Central provides local authentication methods for 2 scenarios
1) Device authentication by shared access signature (SAS) token
2) REST API authentication via API tokens

Devices authenticate with the IoT Central application by using either a shared access signature (SAS) token or an X.509 certificate. X.509 certificates are recommended in production environments.

Lear more about managing device access here: https://docs.microsoft.com/azure/iot-central/core/overview-iot-central-security#manage-device-access

To access an IoT Central application using the REST API, you can create and use an IoT Central API token in addition to using an Azure Active Directory Bearer token. It is currently not possible to block/disable such local authentication but the ability to create/manage API tokens are governed by Role Based Access Control (RBAC) and Organizations.

Learn more about how to authenticate and authorize IoT Central REST API calls here: https://docs.microsoft.com/azure/iot-central/core/howto-authorize-rest-api Avoid the usage of local authentication methods or accounts, these should be disabled wherever possible. Instead use Azure AD to authenticate where possible.

**Configuration Guidance**: Devices authenticate with the IoT Central application by using either a shared access signature (SAS) token or an X.509 certificate. X.509 certificates are recommended in production environments.

**Reference**: [Device authentication](/azure/iot-central/core/overview-iot-central-security#manage-device-access)

### IM-3: Manage application identities securely and automatically

#### Features

##### Managed Identities

**Description**: Data plane actions support authentication using managed identities. [Learn more](/azure/active-directory/managed-identities-azure-resources/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Feature notes**: IoT Central supports system-assigned managed identities to secure connectivity to data egress destinations configured via continuous data export feature.

Learn more about configuring a managed identity for IoT Central applications here: https://docs.microsoft.com/azure/iot-central/core/howto-manage-iot-central-from-portal#configure-a-managed-identity

Learn more about using those managed identities to secure connection to export destinations here: https://docs.microsoft.com/azure/iot-central/core/overview-iot-central-security#authenticate-to-other-services

**Configuration Guidance**: IoT Central supports both types of managed identities: system-assigned and user-assigned.

**Reference**: [Configure a managed identity](/azure/iot-central/core/howto-manage-iot-central-from-portal#configure-a-managed-identity)

##### Service Principals

**Description**: Data plane supports authentication using service principals. [Learn more](/powershell/azure/create-azure-service-principal-azureps).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Feature notes**: IoT Central supports adding Service Principals to data plane access. The service principal must belong to the same Azure Active Directory tenant as the Azure subscription associated with the IoT Central application.

Learn more about how to add service principals as users here: https://docs.microsoft.com/azure/iot-central/core/howto-manage-users-roles#add-users

The Azure Active Directory bearer token associated with the Service Principal can also be used to authenticate and authorize REST API calls.

Learn more about authenticating and authorizing IoT Central REST API calls here: https://docs.microsoft.com/azure/iot-central/core/howto-authorize-rest-api

**Custom Guidance**: Follow the reference to setup Azure AD service principal for authenticate against the API access

**Reference**: [Azure IoT Central API service principal authentication](/rest/api/iotcentral/authentication#service-principal-authentication)

### IM-7: Restrict resource access based on conditions

#### Features

##### Conditional Access for Data Plane

**Description**: Data plane access can be controlled using Azure AD Conditional Access Policies. [Learn more](/azure/active-directory/conditional-access/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Configuration Guidance**: This feature is not supported to secure this service.

## Privileged access

*For more information, see the [Azure Security Benchmark: Privileged access](../security-controls-v3-privileged-access.md).*

### PA-7: Follow just enough administration (least privilege) principle

#### Features

##### Azure RBAC for Data Plane

**Description**: Azure Role-Based Access Control (Azure RBAC) can be used to managed access to service's data plane actions. [Learn more](/azure/role-based-access-control/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Feature notes**: IoT Central currently does not support Azure Role-Based Access Control (Azure RBAC), but provides similar capabilities within IoT Central applications via extensive RBAC, custom roles that cover entire application surface area and Organizations.

Roles enable you to control who within your organization is allowed to do various tasks in IoT Central. There are three built-in roles you can assign to users of your application. You can also create custom roles if you require finer-grained control.

Lear more about managing users and roles here: https://docs.microsoft.com/azure/iot-central/core/howto-manage-users-roles

Learn more about creating a custom role here: https://docs.microsoft.com/azure/iot-central/core/howto-manage-users-roles#create-a-custom-role

Organizations let you define a hierarchy that you use to manage which users can see which devices in your IoT Central application. The user's role determines their permissions over the devices they see, and the experiences they can access. Use organizations to implement a multi-tenanted application.

Organizations are an optional feature that gives you more control over the users and roles in your application.

Learn more about how to manage IoT Central organizations here: https://docs.microsoft.com/azure/iot-central/core/howto-create-organizations

**Configuration Guidance**: This feature is not supported to secure this service.

## Data protection

*For more information, see the [Azure Security Benchmark: Data protection](../security-controls-v3-data-protection.md).*

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

**Feature notes**: Data in-transit encryption (TLS) is enabled by default in the service

**Configuration Guidance**: No additional configurations are required as this is enabled on a default deployment.

### DP-4: Enable data at rest encryption by default

#### Features

##### Data at Rest Encryption Using Platform Keys

**Description**: Data at-rest encryption using platform keys is supported, any customer content at rest is encrypted with these Microsoft managed keys. [Learn more](/azure/security/fundamentals/encryption-atrest#encryption-at-rest-in-microsoft-cloud-services).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | True | Microsoft |

**Configuration Guidance**: No additional configurations are required as this is enabled on a default deployment.

**Reference**: [Azure data at-rest encryption by default](/azure/security/fundamentals/encryption-atrest)

### DP-5: Use customer-managed key option in data at rest encryption when required

#### Features

##### Data at Rest Encryption Using CMK

**Description**: Data at-rest encryption using customer-managed keys is supported for customer content stored by the service. [Learn more](/azure/security/fundamentals/encryption-models).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Configuration Guidance**: This feature is not supported to secure this service.

## Asset management

*For more information, see the [Azure Security Benchmark: Asset management](../security-controls-v3-asset-management.md).*

### AM-2: Use only approved services

#### Features

##### Azure Policy Support

**Description**: Service configurations can be monitored and enforced via Azure Policy. [Learn more](/azure/governance/policy/tutorials/create-and-manage).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Feature notes**: Azure IoT Central supports Azure Policy and offers a variety of built-in policies to support network isolation.

The list of built-in policies supported by Azure IoT Central can be found here: https://docs.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies

**Configuration Guidance**: Use Microsoft Defender for Cloud to configure Azure Policy to audit and enforce configurations of your Azure resources. Use Azure Monitor to create alerts when there is a configuration deviation detected on the resources. Use Azure Policy [deny] and [deploy if not exists] effects to enforce secure configuration across Azure resources.

**Reference**: [Azure Policy built-in policy definitions](/azure/governance/policy/samples/built-in-policies)

## Logging and threat detection

*For more information, see the [Azure Security Benchmark: Logging and threat detection](../security-controls-v3-logging-threat-detection.md).*

### LT-1: Enable threat detection capabilities

#### Features

##### Microsoft Defender for Service / Product Offering

**Description**: Service has an offering-specific Microsoft Defender solution to monitor and alert on security issues. [Learn more](/azure/security-center/azure-defender).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Feature notes**: We are working on it.

**Configuration Guidance**: This feature is not supported to secure this service.

### LT-4: Enable logging for security investigation

#### Features

##### Azure Resource Logs

**Description**: Service produces resource logs that can provide enhanced service-specific metrics and logging. The customer can configure these resource logs and send them to their own data sink like a storage account or log analytics workspace. [Learn more](/azure/azure-monitor/platform/platform-logs-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| False | Not Applicable | Not Applicable |

**Feature notes**: Service metrics is supported but not resource logs.

**Configuration Guidance**: This feature is not supported to secure this service.

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
| False | Not Applicable | Not Applicable |

**Configuration Guidance**: This feature is not supported to secure this service.

## Next steps

- See the [Azure Security Benchmark V3 overview](../overview.md)
- Learn more about [Azure security baselines](../security-baselines-overview.md)
