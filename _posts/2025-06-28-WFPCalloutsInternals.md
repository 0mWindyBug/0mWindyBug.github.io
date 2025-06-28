---
title:  "Windows Filtering Platform internals - Reverse Engineering the callouts mechanism"
date:   2025-06-28
tags: [posts]
excerpt: "Reversing the WFP callout mechanism"
---

## Intro
The Windows Filtering Platform (WFP) is a framework designated for host-based network traffic filtering, replacing the older NDIS and TDI filtering capabilities. WFP exposes both UM and KM apis, offering the ability to block, permit or aduit network traffic based on conditions or deep packet inspection (through "callouts"). As you might have gueesed, WFP is leveraged by the Windows Firewall, Network filters of security products and even rootkits. This blogpost is going to dive into how WFP callouts are managed by the kernel, and use our knowledge to suggest ways to evade components that leverage WFP. 

## The provided sources 
Before we jump right into it, about the blogpost's repo: 
`WFPEnumUM` and `WFPEnumDriver` can be used to enumerate all registered callouts on the system (including their actual addresses, to use just load the driver and run the client). 
`WFPCalloutDriver` is a PoC callout driver (mainly used it for debugging but you can have a look to see the registration process) 


TBC
