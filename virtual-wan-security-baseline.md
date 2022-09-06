---
title: Azure security baseline for Virtual WAN
description: The Virtual WAN security baseline provides procedural guidance and resources for implementing the security recommendations specified in the Azure Security Benchmark.
author: msmbaldwin
ms.service: virtual-wan
ms.topic: conceptual
ms.date: 09/03/2022
ms.author: mbaldwin
ms.custom: subject-security-benchmark

# Important: This content is machine generated; do not modify this topic directly. Contact mbaldwin for more information.

---

# Azure security baseline for Virtual WAN

This security baseline applies guidance from the [Azure Security Benchmark version 3.0](/security/benchmark/azure/overview) to Virtual WAN. The Azure Security Benchmark provides recommendations on how you can secure your cloud solutions on Azure. The content is grouped by the security controls defined by the Azure Security Benchmark and the related guidance applicable to Virtual WAN.

You can monitor this security baseline and its recommendations using Microsoft Defender for Cloud. Azure Policy definitions will be listed in the Regulatory Compliance section of the Microsoft Defender for Cloud dashboard.

When a feature has relevant Azure Policy Definitions, they are listed in this baseline to help you measure compliance to the Azure Security Benchmark controls and recommendations. Some recommendations may require a paid Microsoft Defender plan to enable certain security scenarios.

> [!NOTE]
> **Features** not applicable to Virtual WAN have been excluded. To see how Virtual WAN completely maps to the Azure Security Benchmark, see the **[full Virtual WAN security baseline mapping file](https://github.com/MicrosoftDocs/SecurityBenchmarks/tree/master/Azure%20Offer%20Security%20Baselines/3.0/virtual-wan-azure-security-benchmark-v3-latest-security-baseline.xlsx)**.

## Security profile

The security profile summarizes high-impact behaviors of Virtual WAN, which may result in increased security considerations.

| Service Behavior Attribute | Value |
|--|--|
| Product Category | Networking |
| Customer can access HOST / OS | No Access |
| Service can be deployed into customer's virtual network | False |
| Stores customer content at rest | False |

## Identity management

*For more information, see the [Azure Security Benchmark: Identity management](../security-controls-v3-identity-management.md).*

### IM-8: Restrict the exposure of credential and secrets

#### Features

##### Service Credential and Secrets Support Integration and Storage in Azure Key Vault

**Description**: Data plane supports native use of Azure Key Vault for credential and secrets store. [Learn more](/azure/key-vault/secrets/about-secrets).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Ensure that secrets and credentials are stored in secure locations such as Azure Key Vault, instead of embedding them into code or configuration files.

## Data protection

*For more information, see the [Azure Security Benchmark: Data protection](../security-controls-v3-data-protection.md).*

### DP-3: Encrypt sensitive data in transit

#### Features

##### Data in Transit Encryption

**Description**: Service supports data in-transit encryption for data plane. [Learn more](/azure/security/fundamentals/double-encryption#data-in-transit).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Shared |

**Configuration Guidance**: Enable secure transfer in services where there is a native data in transit encryption feature built in. Microsoft Azure Virtual WAN provides custom routing capabilities and offers encryption for your ExpressRoute traffic. All route management is provided by the virtual hub router, which also enables transit connectivity between virtual networks. Encrypting your ExpressRoute traffic with Virtual WAN provides an encrypted transit between the on-premises networks and Azure virtual networks over ExpressRoute, without going over the public internet or using public IP addresses.

**Reference**: [Encryption in transit](/en/azure/virtual-wan/vpn-over-expressroute)

### DP-6: Use a secure key management process

#### Features

##### Key Management in Azure Key Vault

**Description**: The service supports Azure Key Vault integration for any customer keys, secrets, or certificates. [Learn more](/azure/key-vault/general/overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Shared |

**Configuration Guidance**: Use Azure Key Vault to create and control the life cycle of your encryption keys. Site-to-site VPN in Virtual WAN uses pre-shared keys (PSK) which are discovered, created and managed by the customer in their Azure Key Vault. Implement Credential Scanner to identify credentials within code. Credential Scanner will also encourage moving discovered credentials to more secure locations such as Azure Key Vault.

## Asset management

*For more information, see the [Azure Security Benchmark: Asset management](../security-controls-v3-asset-management.md).*

### AM-2: Use only approved services

#### Features

##### Azure Policy Support

**Description**: Service configurations can be monitored and enforced via Azure Policy. [Learn more](/azure/governance/policy/tutorials/create-and-manage).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Shared |

**Configuration Guidance**: Use Microsoft Defender for Cloud to configure Azure Policy to audit and enforce configurations of your Azure resources. Use Azure Monitor to create alerts when there is a configuration deviation detected on the resources. Use Azure Policy [deny] and [deploy if not exists] effects to enforce secure configuration across Azure resources.

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

**Configuration Guidance**: Enable resource logs for the Virtual Wan service and related resources. A variety of resource logs are available for Virtual WAN and can be configured for the Virtual WAN resource with Azure portal. You can choose to send to Log Analytics, stream to an event hub, or to simply archive to a storage account. Resource logs are supported for both ExpressRoute and P2S/S2S VPNs.

**Reference**: [Resource logs](/azure/virtual-wan/monitor-virtual-wan-reference#diagnostic)

## Next steps

- See the [Azure Security Benchmark V3 overview](../overview.md)
- Learn more about [Azure security baselines](../security-baselines-overview.md)
