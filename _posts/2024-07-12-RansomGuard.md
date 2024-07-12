---
title:  "RansomGuard : writing an anti-ransomware filter driver"
date:   2024-07-12
tags: [posts]
excerpt: "Anti Ransomware minifilter driver"
---

## Intro
Ransomware is one of the most simple - yet significant threats facing organizations today. <br />
Unsuprisingly , the rise and continuing development of ransomware led to a plentitude of research aimed at detecting and preventing it -  AV vendors , independent security reseachers and academies all proposing various solutions to mitigate the threat <br /> 
In this blogpost , we are going cover the existing detection methods , the required internals and walkthrough the design of RansomGuard - a fun open source anti-ransomware minifilter driver we worked on. <br />


## anti-ransomware methods 

#### API monitoring   
Some security solutions monitor API calls , usually flagging suspicious call sequences. 
Whilst monitoring system calls at the kernel level is a worthwhile approach , it's resource-intensive  <br />  
In addition , due to KPP in order for a security solution to hook system calls it will have to either load a hypervisor or leverage techniques like InfinityHook which are bound to be broken , either way such approach may lead to many false positives .

#### HoneyPots 


 
## Entropy 

#### What is it ? 

#### How can it be used to detect encryption 

#### Statictics ? 


 
## The filter manager 


#### What is it , why is it so handy 

#### what can you filter on ? (+Close vs Cleaanup here) 

#### what can you return from your filters (return value) 

#### minifilter contexts 

## The cache manager (Cc) & memory manager (Mm)

#### what is the cache manager ? why do we care ? 

#### caching for file-operations , WriteFile



## Paging I/O 
 
#### what is it ? 
#### why we dont need to filter it for FileObject evaluation ? 
-  we will deal with that later when discussing memory-mapped files 

## Ransomware variations 
 
1. CreateFile -> ReadFile -> (encrypt buffer) -> WriteFile -> CloseFile
2. CreateFile -> CreateFileMapping -> MapViewOfFile -> memcpy to view
3. ReadFile -> DeleteFile -> (encrypt buffer) -> CreateFile (new) -> WriteFile -> CloseFile



## Mitigating variation #1 

#### Design diagram 

#### per - filter description (what does it filter, role , code etc...) 
