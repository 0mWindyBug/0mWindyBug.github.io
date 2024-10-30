---
title:  "AudioGuard :  controlling microphone access on per-process basis"
date:   2024-10-30
tags: [posts]
excerpt: "controlling microphone access on per-process basis"
---

## Intro
Long-term surveillance hinges critically on microphone capture and recording capabilities, serving as a cornerstone of persistent monitoring operations, whether state-sponsored or not. Threat actors can silently harvest sensitive intelligence from team meetings, voice chats, and  internal discussions as long as the endpoint has a microphone device connected to it, providing access to organizational insights. In this blogpost, our goal is to dive into the audio capturing internals on Windows, and to implement a protection that will allow us to restrict microphone access on a per-process basis.

## Some KS terminology 
Whenever we open our webcam, activate our microphone or enable sound. The system needs to read or write related data such as your voice or captured images into RAM. Kernel Streaming (KS) refers to the Microsoft-provided services that support kernel-mode processing of streamed data.  KS serves as a standardized interface for multimedia devices, and aims to provide low latency and simplified multimedia driver development. Microsoft provides three multimedia class driver models: port class, stream class, and AVStream. These class drivers are implemented as export drivers (kernel-mode DLLs) in the system files portcls.sys, stream.sys, and ks.sys. We will breifly discuss the differences between those models later on in the blogpost. 

### KS pins and filters 
Conceptually, a stream undergoes processing as it flows along a data path containing some number of processing nodes. A set of related nodes is grouped together to form a KS filter, which represents a more-or-less independent block of stream-processing functionality. More complex functions can be constructed in a modular way by cascading several filters together to form a filter graph. A KS filter is implemented as a kernel-mode KS object that encapsulates some number of related stream-processing callbacks, described by a [KSFILTER_DESCRIPTOR](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ks/ns-ks-_ksfilter_descriptor) structure. KS filters are connected together through their pins. A pin on an audio filter can be thought of as an audio jack. A client instantiates an input or output pin on a filter when the client needs to route a data stream into or out of that filter. Similarly to a ```KSFILTER```, a ```KSPIN``` is described by a [KSPIN_DESCRIPTOR](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ks/ns-ks-kspin_descriptor). For example, a filter that performs audio mixing might have one [pin factory](https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/pin-factories) that can instantiate a single output pin and a second pin factory that can instantiate several input pins. 

### A short history lesson
