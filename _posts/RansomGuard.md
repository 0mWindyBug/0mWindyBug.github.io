---
title:  "RansomGuard : writing an anti-ransomware filter driver"
date:   2024-07-20
tags: [posts]
excerpt: "Anti Ransomware minifilter driver"

---
Prerequisites
---


Introduction
---


---
Common anti-ransomware methods 
---


--- 
Entropy 
---

# What is it ? 

# How can it be used to detect encryption 

# Statictics ? 


--- 
The filter manager 
---

# What is it , why is it so handy 

# what can you filter on ? (+Close vs Cleaanup here) 

# what can you return from your filters (return value) 

# minifilter contexts 

--- 
The cache manager (Cc) & memory manager (Mm)
---
# what is the cache manager ? why do we care ? 

# caching for file-operations , WriteFile


--- 
Paging I/O 
--- 
# what is it ? 
# why we dont need to filter it for FileObject evaluation ? 
-  we will deal with that later when discussing memory-mapped files 

---
Ransomware variations 
--- 
1. CreateFile -> ReadFile -> (encrypt buffer) -> WriteFile -> CloseFile
2. CreateFile -> CreateFileMapping -> MapViewOfFile -> memcpy to view
3. ReadFile -> DeleteFile -> (encrypt buffer) -> CreateFile (new) -> WriteFile -> CloseFile


---
Mitigating variation #1 
---
# Design diagram 

# per - filter description (what does it filter, role , code etc...) 
