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
Whilst familarity with the filter manager is somewhat neccassery for the rest of the article , I'll  try to provide a brief summary of the basics, otherwise MSDN is your friend. <br/>
In order to tell the filter manager what filters to register , a minifilter calls ```FltRegisterFilter``` , passing the ```FLT_REGISTRATION``` structure : <br/>
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
we will discuss some of it's member later on , for now let's look at the ```OperationRegistration``` field , of type ```FLT_OPERATION_REGISTRATION``` <br/>
``` cpp
typedef struct _FLT_OPERATION_REGISTRATION {
  UCHAR                            MajorFunction;
  FLT_OPERATION_REGISTRATION_FLAGS Flags;
  PFLT_PRE_OPERATION_CALLBACK      PreOperation;
  PFLT_POST_OPERATION_CALLBACK     PostOperation;
  PVOID                            Reserved1;
} FLT_OPERATION_REGISTRATION, *PFLT_OPERATION_REGISTRATION;
```
```MajorFunction``` -> is the operation to filter on (e.g for filtering file reads -> IRP_MJ_READ). <br/>
``` Flags ``` -> a bitmask of flags specifying when to call the preoperation and postoperation filters ( e.g don't call for paging I/O). <br/>
``` PreOperation ```  -> The routine to be called before the operation takes place , with the following prototype: <br/>
```cpp
FLT_PREOP_CALLBACK_STATUS PfltPreOperationCallback(
  [in, out] PFLT_CALLBACK_DATA Data,
  [in]      PCFLT_RELATED_OBJECTS FltObjects,
  [out]     PVOID *CompletionContext
)
```
``` PostOperation ``` -> The routine to be called after the operation took place , with the following prototype: <br/>
```cpp
PFLT_POST_OPERATION_CALLBACK PfltPostOperationCallback;

FLT_POSTOP_CALLBACK_STATUS PfltPostOperationCallback(
  [in, out]      PFLT_CALLBACK_DATA Data,
  [in]           PCFLT_RELATED_OBJECTS FltObjects,
  [in, optional] PVOID CompletionContext,
  [in]           FLT_POST_OPERATION_FLAGS Flags
)
```

where : <br/>
``` Data ``` -> A pointer to the callback data structure for the I/O operation : <br/>
``` cpp
typedef struct _FLT_CALLBACK_DATA {
  FLT_CALLBACK_DATA_FLAGS     Flags;
  PETHREAD                    Thread;
  PFLT_IO_PARAMETER_BLOCK     Iopb;
  IO_STATUS_BLOCK             IoStatus;
  struct _FLT_TAG_DATA_BUFFER *TagData;
  union {
    struct {
      LIST_ENTRY QueueLinks;
      PVOID      QueueContext[2];
    };
    PVOID FilterContext[4];
  };
  KPROCESSOR_MODE             RequestorMode;
} FLT_CALLBACK_DATA, *PFLT_CALLBACK_DATA;
```
``` FltObjects ``` -> A pointer to an FLT_RELATED_OBJECTS structure that contains opaque pointers for the objects related to the current I/O request. <br/>
``` CompletionContext ``` -> context to pass to the post operation routine. <br/>


#### Minifilter contexts 
A context is a structure that is defined by the minifilter driver and that can be associated with a filter manager object.<br/>
The filter manager provides support that allows minifilter drivers to associate contexts with objects to preserve state across I/O operations.<br/>
Contexts are extremley useful , and can be attached to the following objects : <br/>
    * Files 
    * Instances
    * Streams 
    * Stream Handles (File Objects...)
    * Transactions 
    * Volumes 
    
depending on the file system there are certian limitations for attaching contexts , e.g The NTFS and FAT file systems do not support file, stream, or file object contexts on paging files, in the pre-create or post-close path, or for IRP_MJ_NETWORK_QUERY_OPEN operations. <br/>
A minifilter can call ```FltSupports*Contexts``` to check if contexts are supported on a given file object.<br/>


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
