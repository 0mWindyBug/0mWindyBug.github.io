---
title:  "RansomGuard :  an anti-ransomware filter driver"
date:   2024-07-12
tags: [posts]
excerpt: "Anti Ransomware minifilter driver"
---

## Intro
Ransomware is one of the most simple - yet significant threats facing organizations today. <br />
Unsuprisingly , the rise and continuing development of ransomware led to a plentitude of research aimed at detecting and preventing it -  AV vendors , independent security reseachers and academies all proposing various solutions to mitigate the threat <br /> 
This blogpost is going to walkthrough the  design of RansomGuard - a fun open source anti-ransomware minifilter driver we developed, as well as covering some required internals . <br />


## Entropy 
Entropy is a measure of randomness within a set of data. When referenced in the context of information theory and cybersecurity, most people are referring to Shannon Entropy.<br /> This is a specific algorithm that returns a value between 0 and 8 were values near 8 indicate that the data is very random, while values near 0 indicate that the data is very homodulous.<br /> 
Shannon entropy can be a good indicator for detecting the use of packing, compression, and encryption of a file.<br />  Each of the previously mentioned techniques tends to increase the overall entropy of a file. This makes sense intuitively. Let’s take compression for example.<br />  Compression algorithms reduce the size of certain types of data by replacing duplicated parts with references to a single instance of that part. The end result is a file with less duplicated contents. The less duplication there is in a file, the higher the entropy will be because the data is less predictable than it was before.<br /> 
we are going to use entropy as a measure to detect encryption of data <br /> 
the following function gets a pointer to some data and it's size and returns it's shannon entropy value :<br />
```cpp
double utils::CalculateEntropy(PVOID Buffer, size_t Size)
{
    KFLOATING_SAVE FloatState;
    NTSTATUS status = KeSaveFloatingPointState(&FloatState);
    if (!NT_SUCCESS(status))
        return -1;

    ULONG pAlphabet[256] = {};

    size_t cbData = 0;
    for (;;)
    {
        if (cbData == Size)
        {
            break;
        }

        ASSERT(((BYTE*)Buffer)[cbData] < 256);
        pAlphabet[((BYTE*)Buffer)[cbData]]++;

        cbData++;
    }

    double dEntropy = 0.0;
    for (int i = 0; i < 256; i++)
    {
        if (pAlphabet[i] != 0)
        {

            double dTemp = (double)pAlphabet[i] / (double)cbData;
            dEntropy += (-1) * dTemp * log2(dTemp);
        }
    }

    KeRestoreFloatingPointState(&FloatState);
    return dEntropy;
}
```

#### Statistics  



## The filter manager 
the filter manager provides a level of abstraction allowing us  to invest more time into the actual logic of the filter rather than spending time writing a body of "boiler plate" code, and speaking of boiler plate code , writing a legacy file-system filter driver that ** does nothing ** takes 6,000 lines of code. 
Thus, the ultimate solution to the problem was to create a comprehensive “framework” for writing file system filter drivers.<br /> The framework provides the one legacy file system filter driver necessary in the system (fltmgr.sys) , and consumers of the framework plug in as “Minifilters”. This single legacy filter would be serve as a universal file system Filter Manager.<br /> As I/O requests arrive at the Filter Manager legacy filter Device Object, Filter Manager calls the Minifilters using a call out model.<br /> After each Minifilter processes the request, Filter Manager then calls through to the next Device Object in the Device Stack. <br />
It's important to note that easy to write does not mean easy to design , which remains a fairly complex task with minifilters , depending on it's purpose , but it makes it possible to go from design to a working filter in weeks rather than months, which is great. <br />


## Filtering file-system opertions 
a minifilter calls ```FltRegisterFilter``` , passing a ```FLT_REGISTRATION``` structure : 
``` cpp
typedef struct _FLT_REGISTRATION {
  USHORT                                      Size;
  USHORT                                      Version;
  FLT_REGISTRATION_FLAGS                      Flags;
  const FLT_CONTEXT_REGISTRATION              *ContextRegistration;
  const FLT_OPERATION_REGISTRATION            *OperationRegistration;
  PFLT_FILTER_UNLOAD_CALLBACK                 FilterUnloadCallback;
  PFLT_INSTANCE_SETUP_CALLBACK                InstanceSetupCallback;
  PFLT_INSTANCE_QUERY_TEARDOWN_CALLBACK       InstanceQueryTeardownCallback;
  PFLT_INSTANCE_TEARDOWN_CALLBACK             InstanceTeardownStartCallback;
  PFLT_INSTANCE_TEARDOWN_CALLBACK             InstanceTeardownCompleteCallback;
  PFLT_GENERATE_FILE_NAME                     GenerateFileNameCallback;
  PFLT_NORMALIZE_NAME_COMPONENT               NormalizeNameComponentCallback;
  PFLT_NORMALIZE_CONTEXT_CLEANUP              NormalizeContextCleanupCallback;
  PFLT_TRANSACTION_NOTIFICATION_CALLBACK      TransactionNotificationCallback;
  PFLT_NORMALIZE_NAME_COMPONENT_EX            NormalizeNameComponentExCallback;
  PFLT_SECTION_CONFLICT_NOTIFICATION_CALLBACK SectionNotificationCallback;
} FLT_REGISTRATION, *PFLT_REGISTRATION;
```

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
