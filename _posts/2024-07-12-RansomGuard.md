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


## Minifilter contexts 
A context is a structure that is defined by the minifilter driver and that can be associated with a filter manager object.<br/>
The filter manager provides support that allows minifilter drivers to associate contexts with objects to preserve state across I/O operations.<br/>
Contexts are extremley useful , and can be attached to the following objects : <br/>
    - Files <br/>
    - Instances <br/>
    - Streams <br/>
    - Stream Handles (File Objects...) <br/>
    - Transactions <br/>
    - Volumes <br/>
    
Depending on the file system there are certian limitations for attaching contexts , e.g The NTFS and FAT file systems do not support file, stream, or file object contexts on paging files, in the pre-create or post-close path, or for IRP_MJ_NETWORK_QUERY_OPEN operations. <br/>
A minifilter can call ```FltSupports*Contexts``` to check if a context type is supported on a given file object.<br/>

#### Context managment 
Context management is probably one of the most frustrating parts of maintaining a minifilter, your unload hangs ? it's often down to incorrect context managment. this is one (of many) reasons to why you should always enable driver verifier , more on this later : ) <br/>
The filter manager uses reference counting to manage the lifetime of a minifilter context , whenever a context is successfully created,  it is initialized with reference count of one. <br/>
Whenever a context is referenced, for example by a successful context set or get, the filter manager increments the reference count of the context by one. When a context is no longer needed, its reference count must be decremented. A positive reference count means that the context is usable,  When the reference count becomes zero, the context is unusable, and the filter manager eventually frees it. <br/> 
Lastly , note the filter manager is the one responsible for derefencing the Set* reference , not the minifilter - but when ? <br/>
Thanks to the brilliant Rod Widdowson , these are the conditions : <br/>
- The attached to system structure is about to go away. For example, when the file system calls FsRtlTeardownPer StreamContexts as part of tearing down the FCB, the Filter Manager will detach any attached stream contexts and dereference them.</br>
- The filter instance associated with the context is being detached.  Again taking the stream context example, during instance teardown after the InstanceTeardown callbacks have been made the filter manager will detach any stream contexts associated with this instance from their associated ADVANCED_FCB_HEADER and dereference them. <br/>

#### Context registration 
A minifilter passes the following structure to FltRegisterFilter to register context types <br/>
``` cpp
typedef struct _FLT_CONTEXT_REGISTRATION {
  FLT_CONTEXT_TYPE               ContextType;
  FLT_CONTEXT_REGISTRATION_FLAGS Flags;
  PFLT_CONTEXT_CLEANUP_CALLBACK  ContextCleanupCallback;
  SIZE_T                         Size;
  ULONG                          PoolTag;
  PFLT_CONTEXT_ALLOCATE_CALLBACK ContextAllocateCallback;
  PFLT_CONTEXT_FREE_CALLBACK     ContextFreeCallback;
  PVOID                          Reserved1;
} FLT_CONTEXT_REGISTRATION, *PFLT_CONTEXT_REGISTRATION;
```
The ```ContextCleanupCallback``` is called right before the context goes away ,  useful for releasing internal context resources <br/> 


## The NT cache manager 
The windows cache manager is a software-only component which is closely integrated with the windows memory manager , to make file-system data accessible within the virtual memory system <br/>
Although constant advances in storage technologies have led to faster and
cheaper secondary storage devices, accessing data off secondary storage media is
still much slower than accessing data buffered in system memory, so it becomes important to have data
brought into system memory before it is accessed (read-ahead functionality), to
retain such information in memory until it is no longer needed (caching of data),
and possibly to defer writing of modified data to disk to obtain greater efficiency
(write-behind or delayed-write functionality (implemened by the lazy writer).<br/>

## Cached write operation 
Now , consider a write operation initiated by a user application , let's walkthrough the steps and see where the cache manager is involved.<br/>
1. The user application initiates a write operation, which causes control to be
transferred to the I/O Manager in the kernel.<br/>
2. The I/O Manager directs the write request to the appropriate file system
driver using an IRP. the buffer may be mapped to system space , or an mdl may be created or the virtual address of the buffer may be directly passed <br/>
3. The file-system driver recivies the IRP , as long as the operation is buffered (FILE_FLAG_NO_BUFFERING was not passed to CreateFile) , if caching has not yet been initiated for this file, the file system driver initiates caching of the file by invoking the Cache Manager(Cc). The Virtual Memory Manager (Mm) creates a file mapping (section object) for the file to be cached.<br/>
4. The file system driver simply passes on the write request to the cache manager via ```CcCopyWrite``` <br/>
5. The cache manager examines its data structures to determine whether there is a mapped view for the file containing the range of bytes being modified by the user. If no such mapped view exists, the cache manager creates a
mapped view for the file region <br/>
6. The cache manager performs a memory copy operation from the user's buffer to the virtual address range associated with the mapped view for the file. <br/>
7. If the virtual address range is not backed by physical pages, a page faul toccurs and control is transferred to the VMM. <br/>
8. The VMM allocates physical pages, which will be used to contain the requested data <br/>
9. The cache manager completes the copy operation from the user's buffer to the virtual address range associated with the mapped view for the file <br/>
10. The cache manager returns control to the file system driver. The user data is now resident in system memory and has not yet been written to storage. So when is the data actually transfered to storage ? the Cc's lazy writer is responsible to decrease the window in which the cache is dirty by writing cached data back to storage , it coordinates with the mapped page writer thread of the Mm which is responsible to write dirty mapped pages back to storage whenever a certian threshold is met (there's also the modified page writer which shares similar responsbility , with pagefiles). <br/> The noncached write to storage may be initiated by either of them <br/>  
11. The file system driver completes the original IRP sent to it by the I/O manager and the I/O manager completes the original user write request <br/> 

Why should we care ? it's important to keep caching in mind before we think about the design of a file-system filter. <br/>






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
