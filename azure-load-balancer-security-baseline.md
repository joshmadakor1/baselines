---
title: Azure security baseline for Azure Load Balancer
description: The Azure Load Balancer security baseline provides procedural guidance and resources for implementing the security recommendations specified in the Azure Security Benchmark.
author: msmbaldwin
ms.service: load-balancer
ms.topic: conceptual
ms.date: 09/02/2022
ms.author: mbaldwin
ms.custom: subject-security-benchmark

# Important: This content is machine generated; do not modify this topic directly. Contact mbaldwin for more information.

---

# Azure security baseline for Azure Load Balancer

This security baseline applies guidance from the [Azure Security Benchmark version 3.0](/security/benchmark/azure/overview) to Azure Load Balancer. The Azure Security Benchmark provides recommendations on how you can secure your cloud solutions on Azure. The content is grouped by the security controls defined by the Azure Security Benchmark and the related guidance applicable to Azure Load Balancer.

You can monitor this security baseline and its recommendations using Microsoft Defender for Cloud. Azure Policy definitions will be listed in the Regulatory Compliance section of the Microsoft Defender for Cloud dashboard.

When a feature has relevant Azure Policy Definitions, they are listed in this baseline to help you measure compliance to the Azure Security Benchmark controls and recommendations. Some recommendations may require a paid Microsoft Defender plan to enable certain security scenarios.

> [!NOTE]
> **Features** not applicable to Azure Load Balancer have been excluded. To see how Azure Load Balancer completely maps to the Azure Security Benchmark, see the **[full Azure Load Balancer security baseline mapping file](https://github.com/MicrosoftDocs/SecurityBenchmarks/tree/master/Azure%20Offer%20Security%20Baselines/3.0/azure-load-balancer-azure-security-benchmark-v3-latest-security-baseline.xlsx)**.

## Security profile

The security profile summarizes high-impact behaviors of Azure Load Balancer, which may result in increased security considerations.

| Service Behavior Attribute | Value |
|--|--|
| Product Category | Networking |
| Customer can access HOST / OS | No Access |
| Service can be deployed into customer's virtual network | False |
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

**Feature notes**: While the Azure Load Balancer resource does not directly deploy into a Virtual Network, the Internal SKU can create one or more frontend IP configurations using a target Azure Virtual Network.

**Configuration Guidance**: Azure offers two types of Load Balancer offerings, Standard and Basic. Use internal Azure Load Balancers to only allow traffic to backend resources from within certain virtual networks or peered virtual networks without exposure to the internet. Implement an external Load Balancer with Source Network Address Translation (SNAT) to masquerade the IP addresses of backend resources for protection from direct internet exposure.

**Reference**: [Internal Load Balancer Frontend IP configuration](/azure/load-balancer/components#frontend-ip-configuration)

##### Network Security Group Support

**Description**: Service network traffic respects Network Security Groups rule assignment on its subnets. [Learn more](/azure/virtual-network/network-security-groups-overview).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Feature notes**: Users can configure a NSG on their virtual network but not directly on the Load Balancer.

**Configuration Guidance**: Implement network security groups and only allow access to your application's trusted ports and IP address ranges. In cases where there is no network security group assigned to the backend subnet or NIC of the backend virtual machines, traffic will not be allowed to access these resources from the load balancer. Standard Load Balancers provide outbound rules to define outbound NAT with a network security group. Review these outbound rules to tune the behavior of your outbound connections.

The Standard Load Balancer is designed to be secure by default and part of a private and isolated Virtual Network. It is closed to inbound flows unless opened by network security groups to explicitly permit allowed traffic, and to disallow known malicious IP addresses. Unless a network security group on a subnet or NIC of your virtual machine resource exists behind the Load Balancer, traffic is not allowed to reach this resource.

**Reference**: [Azure Load Balancer Frontend IP configuration](/azure/load-balancer/components#frontend-ip-configuration)

**Guidance notes**: Using a Standard Load Balancer is recommended for your production workloads and typically the Basic Load Balancer is only used for testing since the basic type is open to connections from the internet by default and doesn't require network security groups for operation.

## Asset management

*For more information, see the [Azure Security Benchmark: Asset management](../security-controls-v3-asset-management.md).*

### AM-2: Use only approved services

#### Features

##### Azure Policy Support

**Description**: Service configurations can be monitored and enforced via Azure Policy. [Learn more](/azure/governance/policy/tutorials/create-and-manage).

| Supported | Enabled By Default | Configuration Responsibility |
|---|---|---|
| True | False | Customer |

**Configuration Guidance**: Define and implement standard security configurations for Azure resources using Azure Policy. Assign built-in policy definitions related to your specific Azure Load Balancer resources. When there are not built-in Policy definitions available you can use Azure Policy aliases to create custom policies to audit or enforce the configuration of your Azure Load Balancer resources in the 'Microsoft.Network' namespace.

## Next steps

- See the [Azure Security Benchmark V3 overview](../overview.md)
- Learn more about [Azure security baselines](../security-baselines-overview.md)
