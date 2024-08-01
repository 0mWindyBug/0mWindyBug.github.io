---
title:  "RansomGuard :  an anti-ransomware filter driver"
date:   2024-07-12
tags: [posts]
excerpt: "Anti Ransomware minifilter driver"
---


## Intro
Ransomware is one of the most simple - yet significant threats facing organizations today. Unsuprisingly, the rise and continuing development of ransomware led to a plentitude of research aimed at detecting and preventing it -  AV vendors , independent security reseachers and academies all proposing various solutions to mitigate the threat. In this blogpost we are going to walkthrough the design of RansomGuard - an anti-ransomware filter driver we developed , as well as cover the required internals along the way.<br/>

## Entropy 
Entropy is a measure of randomness within a set of data. When referenced in the context of information theory and cybersecurity, most people are referring to Shannon Entropy. This is a specific algorithm that returns a value between 0 and 8 were values near 8 indicate that the data is very random, while values near 0 indicate that the data is very homodulous.<br /> 
Shannon entropy can be a good indicator for detecting the use of packing, compression, and encryption of a file.<br />  Each of the previously mentioned techniques tends to increase the overall entropy of a file. This makes sense intuitively. Let’s take compression for example.<br />  Compression algorithms reduce the size of certain types of data by replacing duplicated parts with references to a single instance of that part. The end result is a file with less duplicated contents. The less duplication there is in a file, the higher the entropy will be because the data is less predictable than it was before. we are going to use entropy as a measure to detect encryption of data.<br/> 
The following function gets a pointer to some data and it's size and returns it's shannon entropy value :<br/>
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

## The filter manager 
The filter manager provides a level of abstraction allowing driver developers to invest more time into the actual logic of the filter rather than writing a body of "boiler plate" code.<br/> Speaking of boiler plate code , writing a legacy file-system filter driver that really **does nothing** can take up to nearly 6,000 lines of code. <br/>
The filter manager is essentially a comprehensive “framework” for writing file system filter drivers. The framework provides the one legacy file system filter driver necessary in the system (fltmgr.sys), and as I/O requests arrive at the filter  manager legacy filter device object, it invokes the registered minifilters using a call out model.<br/>
After each minifilter processes the request, the filter manager then calls through to the next device object in the device stack , if any.<br/>
It's important to note that easy to write does not mean easy to design , which remains a fairly complex task with minifilters, of course - depending on the minifilter's task in hand... Nevertheless it makes it possible to go from design to a working filter in weeks rather than months, which is great. <br />


## Filtering file-system opertions 
Whilst familarity with the filter manager is somewhat neccassery for the rest of the article , I'll  try to provide a brief summary of the basics, in any case MSDN is your friend and feel free to skip this section if you ever worked with the filter manager. <br/>
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
we will discuss some of it's members later on , for now let's look at the ```OperationRegistration``` field , of type ```FLT_OPERATION_REGISTRATION``` <br/>
``` cpp
typedef struct _FLT_OPERATION_REGISTRATION {
  UCHAR                            MajorFunction;
  FLT_OPERATION_REGISTRATION_FLAGS Flags;
  PFLT_PRE_OPERATION_CALLBACK      PreOperation;
  PFLT_POST_OPERATION_CALLBACK     PostOperation;
  PVOID                            Reserved1;
} FLT_OPERATION_REGISTRATION, *PFLT_OPERATION_REGISTRATION;
```
```MajorFunction``` -> is the operation to filter on (e.g. for filtering file reads -> IRP_MJ_READ). <br/>
``` Flags ``` -> a bitmask of flags specifying when to call the preoperation and postoperation filters ( e.g. don't call for paging I/O). <br/>
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
Whenever a context is referenced, for example by a successful context set or get, the filter manager increments the reference count of the context by one. When a context is no longer needed, its reference count must be decremented. A positive reference count means that the context is usable,  when the reference count becomes zero, the context is unusable, and the filter manager eventually frees it. <br/> 
Lastly , note the filter manager is the one responsible for derefencing the Set* reference , it does that in the following conditions: <br/>
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
(write-behind or delayed-write functionality).<br/>

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

Why do we care ? it's important to keep caching in mind before we are moving on to designing our file-system filter. <br/>

## A few words regarding Paging I/O 
Paging I/O is essentially a term used to describe I/O initiated by either the Mm or Cc. For paging reads , it means the page is being read via the demand paging mechanism, and rather than the virtual address of a buffer we are given an MDL that describes the newly allocated physical pages , the read is of course non cached as it must be satisifed from storage.<br/>
For paging writes , it means something within the Virtual Memory System (either Mm or Cc) is requesting that data within the given physical pages will be written back to storage by the file-system driver , much like with a paging read , to flush out dirty pages the O/S builds an MDL to describe the physical pages of the mapping and sends the non-cached, paging write<br/> 
Again , keep these in mind : ) 

## Ransomware variations 
We have to consider all the variants of the encryption process, as it can happen very differently. <br/>
The most popular variation is where the files are opened in R/W, read and encrypted in place, closed, and then (optionally) renamed.<br/> 
Another option is memory mapping the files , from a ransomware prespective not only that it's faster,  it is considered more evasive as the write is initiated by the system process rather than the malicious one (tbh anything asynchrnous is harder to deal with from a defensive point of view), this trick alone was enough for Maze, LockFile and others to evade security solutions.<br/>
Yet another way could be creating a copy of the file with the new name , opened for W, the original file is read, its encrypted content is written inside and the original file is deleted.<br/>
Whilst there are other possiblities , we are going to tackle those 3 as they are (by far) the most commonly implemented by ransomwares in the wild.<br/> 

## Driver Verifier 
Before starting to write our driver , let's talk about verifier briefly. Driver Verifier can subject Windows drivers to a variety of stresses and tests to find improper behavior. You can configure which tests to run, which allows you to put a driver through heavy stress loads and enforce edge cases.<br/>
For a detailed description regarding the various checks avaliable , visit [OSR's post](https://www.osronline.com/article.cfm%5Earticle=325.htm) .<br/>
Enabling verifier during the development process is extremley important for writing a quality driver and debugging efficiently.<br/>
Note that when writing a minifilter you should enable it for both your driver and the fltmgr. <br/>

## Detecting encryption 
We already mentioned entropy as a measure to identify encryption of data, what we also mentioned is the fact compressed data tends to have high entropy.<br/>
To identify encryption has taken place we need to collect two datapoints. First, that represents the initial entropy of the contents of the file, and second that represents the entropy of the contents of the file after modifcation.<br/> 
Based on statistical tests against a large set of files of different types, we came up with the following measurement, that takes into consideration the initial entropy of the file.<br/>

```cpp
// statistical logic to determine encryption 
bool evaluate::IsEncrypted(double InitialEntropy, double FinalEntropy)
{
    if (InitialEntropy == INVALID_ENTROPY || FinalEntropy == INVALID_ENTROPY || InitialEntropy <= 0)
        return false;

    double EntropyDiff = FinalEntropy - InitialEntropy;

    // the lower the initial entropy is the higher the required diff to be considered encrypted 
    double SuspiciousDIff = (MAX_ENTROPY - InitialEntropy) * 0.83;

    if (FinalEntropy >= MIN_ENTROPY_THRESHOLD && (EntropyDiff >= SuspiciousDIff || (InitialEntropy < ENTROPY_ENCRYPTED && FinalEntropy >= ENTROPY_ENCRYPTED) ) )
        return true;

    return false;

}
```
We found 0.83 as the sweet spot value for the coefficient between detecting encrypted files and limiting false positives.<br/>
As we increase the value of the coefficient the difference between the initial entropy value and the final entropy value to be considered suspicious increases. <br/>

## Tracking & Evaluating file handles   
As mentioned ransomware encryption can happen very differently when it comes to file-system operations, we are going to tackle each seperatley as each sequence requires it's own filtering logic.<br/>
Consider the most obvious sequence seen in ransomwares : 
<img src="{{ site.url }}{{ site.baseurl }}/images/RansomSequence1.png" alt="">

There a few things to consider:<br/>
1. A file may be truncated when opened , consequently by the time our filter's post create is invoked the initial state of the file is lost.<br/>
2. A ransomware may initiate several writes using different byte offsets to modify different portions of the same file.<br/>
Considering #1, we will monitor file opens that may truncate the file, indicated by a CreateDisposition value of ```FILE_SUPERSEDE``` , ```FILE_OVERWRITE``` or ```FILE_OVERWRITE_IF```. In such cases the initial state of the file is captured in pre create, otherwise it is captured when the first write occurs - in pre write.<br/>
Considering #2 , the post modification state of the file is captured whenever whenever IRP_MJ_CLEANUP is sent.<br/>
that is, whenever the last handle to a file object is closed (represents the usermode state), in contrast IRP_MJ_CLOSE is sent whenever the last reference is released from the file object (represents the system state). <br/>
Whenever I need a reminder of what's allowed in PostCleanup , I go to the FAT source code and look for the check it does. The following can be seen in the ```FatCheckIsOperationLegal``` :

```cpp
        //
    //  If the file object has already been cleaned up, and
    //
    //  A) This request is a paging io read or write, or
    //  B) This request is a close operation, or
    //  C) This request is a set or query info call (for Lou)
    //  D) This is an MDL complete
    //
    //  let it pass, otherwise return STATUS_FILE_CLOSED.
    //

    if ( FlagOn(FileObject->Flags, FO_CLEANUP_COMPLETE) ) {

        PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation( Irp );

        if ( (FlagOn(Irp->Flags, IRP_PAGING_IO)) ||
             (IrpSp->MajorFunction == IRP_MJ_CLOSE ) ||
             (IrpSp->MajorFunction == IRP_MJ_SET_INFORMATION) ||
             (IrpSp->MajorFunction == IRP_MJ_QUERY_INFORMATION) ||
             ( ( (IrpSp->MajorFunction == IRP_MJ_READ) ||
                 (IrpSp->MajorFunction == IRP_MJ_WRITE) ) &&
               FlagOn(IrpSp->MinorFunction, IRP_MN_COMPLETE) ) ) {

            NOTHING;

        } else {

            FatRaiseStatus( IrpContext, STATUS_FILE_CLOSED );
        }
    }
   
```

Of course other file systems might allow other things, but FAT is always a good baseline.<br/>
Clearly , a non paging write is not allowed , so it's safe to assume the file will not be modified (again , excluding paging I/O - we will deal with that later)  after the handle is closed by the user which makes post cleanup good enough to use as our second datapoint.<br/>
The following diagram summarizes RansomGuard's design for evaluating operations across the same handle.<br/>

<img src="{{ site.url }}{{ site.baseurl }}/images/RansomGuardDesign.png" alt="">

Next , let's walkthrough each filter.<br/> 
For the full implementation of the filters : [filters.cpp source](https://github.com/0mWindyBug/RansomGuard/blob/main/RansomGuardBeta/RansomGuard/filters.cpp).

### PreCreate 
Generally speaking , the PreCreate filter is responsible to filter out any uninteresting I/O requests. For now , we are only interested in file opens for R/W , from usermode (so yea , not filtering new files , altough that's going to change later on in the blogpost).<br/>
In addition , as we've discussed earlier this is our only chance to capture the initial state of truncated files , if the file might get truncated - we read the file , calculate it's entropy, backup it's contents in memory and pass it all to PostCreate.<br/>
Lastly , we also use this filter to enforce access restrictions : <br/>
* The restore directory shpould be accessible only from kernel mode.
  - The user can connect to RansomGuard's filter port and issue a control to copy the files to a user-accesible location. <br/>
* A process marked as malicious(ransomware) is blocked from any file-system access.
<br/>

Let's walkthrough the code , starting with the encforcment of file-system access restrictions : 
```cpp
	// block any file-system access by malicious processes 
	ProcessesListMutex.Lock();
	pProcess ProcessInfo = processes::GetProcessEntry(FltGetRequestorProcessId(Data));
	if (ProcessInfo)
	{
		if (ProcessInfo->Malicious)
		{
			ProcessesListMutex.Unlock();
			DbgPrint("[*] blocked malicious process from file-system access\n");
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}

	}
	ProcessesListMutex.Unlock();

	// block any usermode access to the restore directory 
	FilterFileNameInformation FileNameInfo(Data);
	if (!FileNameInfo.Get())
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	status = FileNameInfo.Parse();
	if (!NT_SUCCESS(status))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	
	if (restore::IsRestoreParentDir(FileNameInfo->ParentDir) && Data->RequestorMode == UserMode)
	{
		DbgPrint("[*] blocked usermode access to the restore directory\n");
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}
```
we are not interested in requests from kernel mode or not for writing  : 
```cpp
	// Skip kernel mode or non write requests
	const auto& params = Data->Iopb->Parameters.Create;
	if (Data->RequestorMode == KernelMode
		|| (params.SecurityContext->DesiredAccess & FILE_WRITE_DATA) == 0 )
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
```
handling TRUNCATE_EXISTING opens : 
```cpp
	ULONG Options = params.Options;

	// if file might going to be truncated in post create try to read it now
	ULONG CreateDisposition = (Options >> 24) & 0x000000ff;

	// we are going to invoke the post callback , so allocate a context to pass information to it 
	pCreateCompletionContext CreateContx = (pCreateCompletionContext)FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, sizeof(CreateCompletionContext), TAG);
	if (!CreateContx)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	CreateContx->PreEntropy = INVALID_ENTROPY;
	CreateContx->OriginalContent = nullptr;
	CreateContx->InitialFileSize = 0;
	CreateContx->SavedContent = false;
	CreateContx->CalculatedEntropy = false;

	// if file might get truncated 
	if (CreateDisposition == FILE_OVERWRITE || CreateDisposition == FILE_OVERWRITE_IF || CreateDisposition == FILE_SUPERSEDE)
	{
		FilterFileNameInformation FileNameInfo(Data);
		PFLT_FILE_NAME_INFORMATION NameInformation = FileNameInfo.Get();
		if (!NameInformation)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance, CreateContx, TAG);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		CreateContx->PreEntropy = utils::CalculateFileEntropyByName(FltObjects->Filter, FltObjects->Instance, &NameInformation->Name, FLT_CREATE_CONTEXT, CreateContx);
		if (CreateContx->PreEntropy == INVALID_ENTROPY)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance, CreateContx, TAG);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		CreateContx->CalculatedEntropy = true;
	}
	*CompletionContext = CreateContx;
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}
```

A process notify routine managed linked list is used to track active processes in the system and maintain process state across different file-system operations, each process described by the following struct : <br/>

```cpp
typedef struct _Process
{
	ULONG Pid; 
	ULONG OriginalPid;
	ULONG ParentPid;
	PUNICODE_STRING ImagePath; 
	int FilesEncrypted;
	LIST_ENTRY* Next;
	bool Suspicious;
	bool Malicious;
	bool Terminated;
	pSection SectionsOwned;
	int SectionsCount;
	Mutex SectionsListLock;
} Process, * pProcess;
```
Since we use a statistical logic to identify encryption , we set a threshold of encrypted files by a process in which we consider it as ransomware, the ```EncryptedFiles``` counter is used for that matter, the rest of the structure will make sense later on in the blogpost. <br/> 

### PostCreate 
In our PostCreate filter , if the file is not new and the file-system supports FileObject contexts for the given operation(not supported in the paging I/O path) -  we initialize our FileObject context structure and attach it to the file object:

```cpp
typedef struct _HandleContext
{
	PFLT_FILTER Filter;
	PFLT_INSTANCE Instance;
	UNICODE_STRING FileName;
	UNICODE_STRING FinalComponent;
	ULONG RequestorPid;
	bool WriteOccured;
	double PreEntropy;
	double PostEntropy;
	PVOID OriginalContent;
	ULONG InitialFileSize;
	bool SavedContent;
}HandleContext, * pHandleContext;

```
Checking for FileObject context support and filtering out new files : 
```cpp
	pCreateCompletionContext PreCreateInfo = (pCreateCompletionContext)CompletionContext;

	if (Flags & FLTFL_POST_OPERATION_DRAINING || !FltSupportsStreamHandleContexts(FltObjects->FileObject) || Data->IoStatus.Information == FILE_DOES_NOT_EXIST)
	{
		if (PreCreateInfo->SavedContent)
			ExFreePoolWithTag(PreCreateInfo->OriginalContent,TAG);

		FltFreePoolAlignedWithTag(FltObjects->Instance, CompletionContext, TAG);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	const auto& params = Data->Iopb->Parameters.Create;

```
Allocating , initializing and attaching a context to the FileObject : 
```cpp
	pHandleContext HandleContx = nullptr;
	NTSTATUS status = FltAllocateContext(FltObjects->Filter, FLT_STREAMHANDLE_CONTEXT, sizeof(HandleContext), NonPagedPool, reinterpret_cast<PFLT_CONTEXT*>(&HandleContx));
	if (!NT_SUCCESS(status))
	{
		if (PreCreateInfo->SavedContent)
			ExFreePoolWithTag(PreCreateInfo->OriginalContent, TAG);
		FltFreePoolAlignedWithTag(FltObjects->Instance, CompletionContext, TAG);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	...
	// initialization of context stripped for readabilty , check out filters.cpp for the initialization code.
	...

	status = FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, reinterpret_cast<PFLT_CONTEXT>(HandleContx), nullptr);
	if (!NT_SUCCESS(status))
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	FltReleaseContext(HandleContx);
	return FLT_POSTOP_FINISHED_PROCESSING;
}
```

### PreWrite 
If the FileObject is monitored (has a context attached to it) , and if it's the first write using the FileObject , capture the initial state of the file. <br/>

```cpp
// filtering logic for any I/O other than noncached paging I/O 
	pHandleContext HandleContx = nullptr;
	status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, reinterpret_cast<PFLT_CONTEXT*>(&HandleContx));
	if (!NT_SUCCESS(status))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	AutoContext AutoHandleContx(HandleContx);
	
	// this is true if the file was opened as truncated or it's not the first write using the handle 
	if (HandleContx->WriteOccured)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	HandleContx->WriteOccured = true;
	
	HandleContx->PreEntropy = utils::CalculateFileEntropy(FltObjects->Instance, FltObjects->FileObject, HandleContx, true);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
```
within ```utils::CalculateFileEntropy``` , the original content of the file is backed up in the context.<br/>
```cpp
 Entropy = utils::CalculateEntropy(DiskContent, FileInfo.EndOfFile.QuadPart);

        if (InitialEntropy && Context)
        {
            Context->OriginalContent = DiskContent;
            Context->InitialFileSize = FileInfo.EndOfFile.QuadPart;
            Context->SavedContent = true;
        }

```

### PreCleanup 
Again , simply check if the file is monitored and a write has been made, if not there's no need to evaluate the context. <br/>

```cpp
	pHandleContext HandleContx = nullptr;
	NTSTATUS status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, reinterpret_cast<PFLT_CONTEXT*>(&HandleContx));
	if (!NT_SUCCESS(status))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// no write occured , no need to evaluate 
	if (!HandleContx->WriteOccured)
	{
		FltReleaseContext(HandleContx);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	// pass handle context pointer to post cleanup 
	*CompletionContext = HandleContx;
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;

```

### PostCleanup 
At this point the file cannot be modified using the same handle , due to IRQL restrictions capturing the second datapoint must be deferred to a worker thread, this is done by returning ```FLT_POSTOP_MORE_PROCESSING_REQUIRED```.  <br/>

```cpp
	pHandleContext HandleContx = (pHandleContext)CompletionContext;
	if (!HandleContx)
		return FLT_POSTOP_FINISHED_PROCESSING;
	if (Flags & FLTFL_POST_OPERATION_DRAINING)
	{
		// release get reference from pre close 
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	// continue completion processing asynchronously at passive level 
	PFLT_DEFERRED_IO_WORKITEM EvalWorkItem = FltAllocateDeferredIoWorkItem();
	if (!EvalWorkItem)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	NTSTATUS status = FltQueueDeferredIoWorkItem(EvalWorkItem, Data, evaluate::EvaluateHandle, DelayedWorkQueue, reinterpret_cast<PVOID>(HandleContx));
	if (!NT_SUCCESS(status))
	{
		FltFreeDeferredIoWorkItem(EvalWorkItem);
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	return FLT_POSTOP_MORE_PROCESSING_REQUIRED;


```
### The evaluate::EvaluateHandle work item

```cpp
VOID evaluate::EvaluateHandle(PFLT_DEFERRED_IO_WORKITEM FltWorkItem, PFLT_CALLBACK_DATA Data, PVOID Context)
{
    pHandleContext HandleContx = (pHandleContext)Context;
    ULONG FileSize = 0;
    HandleContx->PostEntropy = utils::CalculateFileEntropyByName(HandleContx->Filter, HandleContx->Instance, &HandleContx->FileName, FLT_NO_CONTEXT, nullptr);

    double EntropyDiff = HandleContx->PostEntropy - HandleContx->PreEntropy;
    if (evaluate::IsEncrypted(HandleContx->PreEntropy, HandleContx->PostEntropy))
    {
        if (HandleContx->OriginalContent && HandleContx->InitialFileSize > 0)
        {
            if (NT_SUCCESS(restore::BackupFile(&HandleContx->FinalComponent, HandleContx->OriginalContent, HandleContx->InitialFileSize)))
                DbgPrint("[*] backed up %wZ\n", HandleContx->FileName);
        }
        processes::UpdateEncryptedFiles(HandleContx->RequestorPid);
    }

    FltReleaseContext(HandleContx);
    FltFreeDeferredIoWorkItem(FltWorkItem);
    FltCompletePendedPostOperation(Data);
}

```
where ```processes::UpdateEncryptedFiles``` increases the process's ```EncryptedFiles``` counter and terminates it if the threshold is met.<br/>

### RansomGuard against WannaCry 
Knowing WannaCry follows the CreateFile -> ReadFile -> WriteFile -> CloseFile sequence , we tested what we have so far against it : 
* 10 files encrypted , 10 of which RansomGuard restored ! 
* successfully killed WannaCry
* Debug output : 

```yaml
00000296	167.18316650	[FltMgr] Mini-filter verification enabled for "RansomGuard" filter.	
00000297	167.19189453	[*] RansomGuard protection is active!		
00000391	217.50335693	[*] Encryption Detected	
00000392	230.13081360	[*] backed up \Device\HarddiskVolume3\Users\dorge\Desktop\9781118127698.jpg	
00000393	230.14079285	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\WannaCry.exe -> 1		
00000411	236.85186768	[*] Encryption Detected	
00000412	236.95446777	[*] backed up \Device\HarddiskVolume3\Users\dorge\Desktop\IMG-20170621-WA0005.jpg	
00000413	236.96711731	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\WannaCry.exe -> 2		
00000421	238.28771973	[*] Encryption Detected	
00000422	238.31800842	[*] backed up \Device\HarddiskVolume3\Users\dorge\Desktop\IMG-20170623-WA0009.jpg	
00000423	238.32882690	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\WannaCry.exe -> 3	
00000424	239.00428772	[*] [\Device\HarddiskVolume3\Windows\Prefetch\CMD.EXE-6D6290C5.pf] pre write 7643 post close 7640 diff -3	
00000427	239.56579590	[*] [\Device\HarddiskVolume3\Users\dorge\Desktop\IMG_20170704_104906.jpg] pre write 7971 post close 8000 diff 29	
00000428	239.58071899	[*] Encryption Detected	
00000429	239.69236755	[*] backed up \Device\HarddiskVolume3\Users\dorge\Desktop\IMG_20170704_104906.jpg	
00000430	239.70263672	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\WannaCry.exe -> 4	
00000439	241.63113403	[*] Encryption Detected	
00000440	241.70027161	[*] backed up \Device\HarddiskVolume3\Users\dorge\Desktop\IMG_20180228_170753.jpg	
00000441	241.71061707	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\WannaCry.exe -> 5	
00000444	243.08477783	[*] [\Device\HarddiskVolume3\Users\dorge\Desktop\IMG-20141130-WA0000.jpg] pre write 7971 post close 7999 diff 29	
00000445	243.09956360	[*] Encryption Detected	
00000446	243.24313354	[*] backed up \Device\HarddiskVolume3\Users\dorge\Desktop\IMG-20141130-WA0000.jpg	
00000447	243.25639343	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\WannaCry.exe -> 6		
00000461	248.49011230	[*] Encryption Detected	
00000462	248.49717712	[*] backed up \Device\HarddiskVolume3\Users\dorge\Desktop\IMG_20190620_082327.jpg	
00000463	248.50477600	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\WannaCry.exe -> 7	
00000465	248.52275085	[*] Encryption Detected	
00000466	248.52947998	[*] backed up \Device\HarddiskVolume3\Users\dorge\Desktop\LICENSE.txt	
00000467	248.53729248	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\WannaCry.exe -> 8	
00000468	248.55439758	[*] backed up \Device\HarddiskVolume3\Users\dorge\Desktop\Screenshot_20230308-232838_Gallery.jpg	
00000469	248.56340027	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\WannaCry.exe -> 9	
00000473	249.27931213	[*] Encryption Detected	
00000474	249.43690491	[*] backed up \Device\HarddiskVolume3\Users\dorge\Desktop\Screenshot_20230325-185808_Chrome.jpg	
00000475	249.44566345	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\WannaCry.exe -> 10	
00000476	249.45210266	[*] killed ransomware process!	
```

## Filtering Memory Mapped I/O 
Usage of memory mapped files to perform the encryption has become more and more common around ransomware families over the years, which makes it harder for behavior based anti-ransomware solutions to keep track of what is going on, as mentioned this is due to the nature of memory mapped I/O.<br/>
<img src="{{ site.url }}{{ site.baseurl }}/images/RansomSequence2.png" alt="">

A file mapping is essentially a section object , with ```CreateFileMapping``` being a wrapper around ```NtCreateSection```.
To write to a mapped file , an application maps a view of the file to the process and operates on the pages backing the view directly, as a result the corresponding PTEs are marked as dirty , when the virtual address range is flushed or unmapped the dirty PTE bit is "pushed out" to the PFN (i.e. the Modified bit gets set). Mofidied PFNs are written out back to storage asynchrnously by one of the page writers , for file backed sections by the mapped page writer , and for pagefile backed sections by the modified page writer.<br/>

From the ransomware perspective this is great , the actual write to the file seems as if it was originated from the system process, it can even happen after the process is terminated , and since the ransomware process itself only interacts with memory rather than disk , it's also much faster.
Our goal is to be able not only to detect those mapped page writer encryptions , but to pinpoint back at the malicious process behind them.<br/>

### Synhcrnous Flush 
Whilst I personally haven't seen such usage in ransomwares, an application can explictly call  ```FlushViewOfFile``` to flush changes back to storage synchrnously , in which case the nature of the paging write is different.<br/>
```FlushViewOfFile``` maps to ```MmFlushVirtualMemory``` in ntos , which in turn calls ```MmFlushSectionInternal``` as shown below : <br/>
<img src="{{ site.url }}{{ site.baseurl }}/images/AcquireCc.png" alt="">

Followed by the following callstack : <br/> 
<img src="{{ site.url }}{{ site.baseurl }}/images/SynchrnousFlush.png" alt="">

Clerarly , ```MmFlushSectionInternal``` , where the actual write is initiated , is surrounded by two FsRtl callbacks :
* ```FsRtlAcquireFileForCcFlushEx``` - ```IRP_MJ_ACQUIRE_FOR_CC_FLUSH``` (before the write)
* ```FsRtlReleaseFileForCcFlushEx``` - ```IRP_MJ_RELEASE_FOR_CC_FLUSH``` (after the write)

Most importantly , for a synchrnous flush the write is initiated from the caller's context (which is why it's unlikely to see it used in a ransomware). <br/>

### Asynchrnous mapped page writer write 
In contrast , for an asynchrnous mapped page writer write two different FsRtl callbacks are invoked  : <br/>
* ```FsRtlAcquireFileForModWriteEx``` - ```IRP_MJ_ACQUIRE_FOR_MOD_WRITE``` (before the write)
* ```FsRtlReleaseFileForModWriteEx``` - ```IRP_MJ_RELEASE_FOR_MOD_WRITE``` (after the write)

This can be easily seen in ```MiMappedPageWriter``` -> ```MiGatherMappedPages``` which eventually calls ```IoAsynchrnousPageWrite``` or alternatively, in Procmon with advanced output enabled.<br/> 
<img src="{{ site.url }}{{ site.baseurl }}/images/AcquireForMod.png" alt="">

Note ```IRP_MJ_RELEASE_FOR_MOD_WRITE``` is typically invoked as part of a special kernel APC , and always runs at IRQL == APC_LEVEL. <br/>

Altough not used in RansomGuard, using the Acquire/Release callbacks as two datapoints to filter memory mapped I/O writes is a possability.<br/>

### Building asynchrnous context 
To connect between a mapped page writer write and the process that memory mapped the file , we have to monitor the creation of section objects.<br/> The heuristic idea is to assume any process that created a R/W section object for the file might be the one that modified the mapping and triggered the asynchrnous write, that means , whenever our minifilter sees a mapped page writer encryption , we will traverse each process and check if it ever created a R/W section for file in question , if so , it's ```EncryptedFiles``` counter will be increased.<br/> The odds for two different processes (one being a ransomware and the other being legitimiate) , to create R/W section objects for the same X number of files , and for those X number of files to also get encrypted are very slim to say the least , and so is the risk for false positives.<br/>

To track the creation of section objects we can filter ```IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION```, we are only interested in the creation of R/W section objects from UserMode : 
```cpp
if(Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection && Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection == PAGE_READWRITE && Data->RequestorMode == UserMode)
```
If that's indeed the case: 
* If not attached yet , a file context is allocated and attached to the file , initialized with the file name.
* the name of the file being mapped is added to a linked list (```SectionsOwned```) of files mapped by the process (under the process entry structure).

```cpp

// if new r/w section was created 
	if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection && Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection == PAGE_READWRITE && Data->RequestorMode == UserMode)
	{
		pFileContext FileContx = nullptr;

		// allocate FileContext if it does not exist 
		NTSTATUS status = FltGetFileContext(FltObjects->Instance, FltObjects->FileObject, reinterpret_cast<PFLT_CONTEXT*>(&FileContx));
		if (!NT_SUCCESS(status))
		{

			status = FltAllocateContext(FltObjects->Filter, FLT_FILE_CONTEXT, sizeof(FileContext), NonPagedPool, reinterpret_cast<PFLT_CONTEXT*>( &FileContx));
			if (!NT_SUCCESS(status))
				return FLT_PREOP_SUCCESS_NO_CALLBACK;

			FilterFileNameInformation FileNameInfo(Data);
			if (!FileNameInfo.Get())
			{
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}

			// init file name in context 
			status = FileNameInfo.Parse();
			if (!NT_SUCCESS(status))
			{
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}

			FileContx->FileName.MaximumLength = FileNameInfo->Name.MaximumLength;
			FileContx->FileName.Length = FileNameInfo->Name.Length;
			if (FileNameInfo->Name.Length == 0 || !FileNameInfo->Name.Buffer)
			{
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			FileContx->FileName.Buffer = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, FileNameInfo->Name.MaximumLength, TAG);
			if (!FileContx->FileName.Buffer) {
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			RtlCopyUnicodeString(&FileContx->FileName, &FileNameInfo->Name);


			FileContx->FinalComponent.MaximumLength = FileNameInfo->FinalComponent.MaximumLength;
			FileContx->FinalComponent.Length = FileNameInfo->FinalComponent.Length;

			if (FileNameInfo->FinalComponent.Length == 0 || !FileNameInfo->FinalComponent.Buffer)
			{
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			FileContx->FinalComponent.Buffer = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, FileNameInfo->FinalComponent.MaximumLength, TAG);
			if (!FileContx->FinalComponent.Buffer) {
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			RtlCopyUnicodeString(&FileContx->FinalComponent, &FileNameInfo->FinalComponent);

			// set context to file 
			status = FltSetFileContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, FileContx, nullptr);
			if (!NT_SUCCESS(status))
			{
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			


			DbgPrint("[*] R/W section is created for %wZ\n", FileContx->FileName);

		}

		// track section in process section list  
		AutoLock<Mutex>process_list_lock(ProcessesListMutex);
		pProcess ProcessEntry = processes::GetProcessEntry(FltGetRequestorProcessId(Data));
		if (!ProcessEntry)
		{
			FltReleaseContext(FileContx);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		sections::AddSection(&FileContx->FileName, ProcessEntry);

		FltReleaseContext(FileContx);
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
```

### Noncached paging I/O PreWrite filtering
We know memory mapped I/O , regardless if synchrnous (explicit flush) or asynchrnous (mapped / modified page writer write) comes in the form of noncached paging I/O.<br/> 
Up until now , such I/O has been indirectly filtered out as it has no support for FileObject contexts, we can add the following check at the start of our PreWrite filter.<br/>
```cpp
// not interested in writes to the paging file 
	if (FsRtlIsPagingFile(FltObjects->FileObject))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	

	// if noncached paging I/O and not to the pagefile
	if (FlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE) && FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
```																	  
Next , we are going to check if the file has a file context attached to it , as we are only interested in noncached paging writes to files that have been previously mapped by UM processes.<br/>
```cpp
pFileContext FileContx;

		// if there's a file context for the file 
		status = FltGetFileContext(FltObjects->Instance, FltObjects->FileObject, reinterpret_cast<PFLT_CONTEXT*>(&FileContx));
		if (!NT_SUCCESS(status))
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
```
Since the mapped page writer flush takes percisley one write , we can reliably capture both of our datapoints already in pre write, we know about the state of the file before the write and we know what is going to be written.<br/>
RansomGuard simulates the write in memory as shown below: 
```cpp
auto& WriteParams = Data->Iopb->Parameters.Write;
		if (WriteParams.Length == 0)
		{
			FltReleaseContext(FileContx);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}


		// retrive the data to be written 
		if (WriteParams.MdlAddress != nullptr)
		{
			DataToBeWritten = MmGetSystemAddressForMdlSafe(WriteParams.MdlAddress,NormalPagePriority | MdlMappingNoExecute);
			if (!DataToBeWritten)
			{
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
		}
		// no mdl was provided so use buffer 
		else
		{
			DataToBeWritten = WriteParams.WriteBuffer;
		}
		
		DataCopy = ExAllocatePoolWithTag(NonPagedPool, WriteParams.Length, TAG);
		if (!DataCopy)
		{
			FltReleaseContext(FileContx);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		// read file from disk and make a copy of it 
		ULONG FileSize = utils::GetFileSize(FltObjects->Instance, FltObjects->FileObject);
		if (FileSize == 0)
		{
			FltReleaseContext(FileContx);
			ExFreePoolWithTag(DataCopy, TAG);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		PVOID DiskContent = utils::ReadFileFromDisk(FltObjects->Instance, FltObjects->FileObject);
		if (!DiskContent)
		{
			FltReleaseContext(FileContx);
			ExFreePoolWithTag(DataCopy, TAG);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		// make a copy of the buffer , must be done in try-except since there's a possibility it's a user buffer. 
		__try {

			RtlCopyMemory(DataCopy,
				DataToBeWritten,
				WriteParams.Length);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			FltReleaseContext(FileContx);
			ExFreePoolWithTag(DiskContent, TAG);
			ExFreePoolWithTag(DataCopy, TAG);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
// simulate a write in memory 
		SIZE_T SimulatedSize = (FileSize > WriteParams.ByteOffset.QuadPart + WriteParams.Length) ? FileSize : 		WriteParams.ByteOffset.QuadPart + WriteParams.Length;
		PVOID SimulatedContent = ExAllocatePoolWithTag(NonPagedPool,SimulatedSize, TAG);
		if (!SimulatedContent)
		{
			FltReleaseContext(FileContx);
			ExFreePoolWithTag(DiskContent,TAG);
			ExFreePoolWithTag(DataCopy, TAG);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		RtlCopyMemory(SimulatedContent, DiskContent, FileSize);
		RtlCopyMemory((PVOID)((ULONG_PTR)SimulatedContent + WriteParams.ByteOffset.QuadPart), DataCopy, WriteParams.Length);

```
Now that we have two datapoints we can evaluate the contents in the buffers : 
```cpp
	// evaluate buffers 
		PreEntropy  = utils::CalculateEntropy(DiskContent, FileSize);
		PostEntropy = utils::CalculateEntropy(SimulatedContent, FileSize);

		double EntropyDiff = PostEntropy - PreEntropy;

		DbgPrint("[*] [%wZ] pre paging write %d predicted paging write %d diff %d\n", FileContx->FileName, (int)ceil(PreEntropy * 1000), (int)ceil(PostEntropy  * 1000), (int)ceil(EntropyDiff * 1000));

		if (evaluate::IsEncrypted(PreEntropy, PostEntropy))
		{
			ULONG RequestorPid = FltGetRequestorProcessId(Data);

			// synchrnous -> explicit flush 
			if (FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO) && RequestorPid != SYSTEM_PROCESS)
			{
				DbgPrint("[*] %wZ encrypted by %d\n", FileContx->FileName, RequestorPid);
				processes::UpdateEncryptedFiles(RequestorPid);
			}
			// asynchrnous -> mapped page writer write 
			else
			{
				DbgPrint("[*] %wZ encrypted by mapped page writer\n",FileContx->FileName);
				processes::UpdateEncryptedFilesAsync(&FileContx->FileName);

			}
			if (NT_SUCCESS(restore::BackupFile(&FileContx->FileName, DiskContent, FileSize)))
				DbgPrint("[*] backed up %wZ\n", FileContx->FinalComponent);
		}

```
If the operation is synchrnous, business as usual as we are in the caller's context. otherwise we call ```processes::UpdateEncryptedFilesAsync``` in which we increment the ```EncryptedFiles``` counter of any process that previously created a R/W section object for the encrypted file.<br/>

In theory , there's a chance for a process to modify thousands of file mappings and terminate before the mapped page writer activates. Rewind when a process is terminated , our process notify routine is invoked and the process entry structure is freed - we lose all tracking information we had on that process.<br/> To handle such case , if the process terminated has created more than a threshold number of R/W sections , it's removal from the list is deffered to a dedicated system thread : 
```cpp
pProcess ProcessEntry = processes::GetProcessEntry(HandleToUlong(ProcessId));
		if (!ProcessEntry)
			return;

		ProcessEntry->Terminated = true;
		ProcessEntry->OriginalPid = ProcessEntry->Pid;
		ProcessEntry->Pid = INVALID_PID;

		if (ProcessEntry->SectionsCount >= NUMBER_OF_SECTIONS_TO_DEFER_REMOVAL)
		{
			NTSTATUS status;
			HANDLE ThreadHandle;
			status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, processes::DeferredRemover, ProcessEntry);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("[*] could not defer removal to system thread : ( \n");
				processes::RemoveProcess(HandleToUlong(ProcessId));
			}
		}
```
The system thread waits for two minutes and removes the entry , we also have to "fake" the pid to avoid ambiguity conflicts (i.e. a new process is created with the same pid that have just been terminated.)<br/>

### Blocking a mapped page writer write 
As mentioned a process may be able to modify a large number of views before the mapped page writer activates. We can't prevent those modifications by killing the process , the paging writes have already been "scheduled" as the PTEs are marked as dirty. <br/> Once we know a ransomware is executing, and is using memory mapped I/O to encrypt files, we'd like to prevent any modification to a file that is backed by a R/W section created by the process classified as ransomware.<br/> We cant block the write (i.e. by returning access denied and FLT_PREOP_COMPLETE) as in such case  the PFN will remain modified - inevtibaly causing the mapped page writer to trigger again.
One option could be to lie and "successfully" complete the IRP :

```cpp
Data->Iosb.Status = STATUS_SUCCESS;
Data->Iosb.Information = Data->Iopb->Parameters.Write.Length;
return FLT_PREOP_COMPLETE
```
Whilst it will indeed prevent the modification, it can lead to major cache coherncey issues eventually causing applications to fail and potentially the machine to crash.<br/>
Instead we are going to take the apprach below , the comment describes it well enough : 
```cpp
		// if a malicious process has a R/W section object to this file we want to prevent the modification
		// we cant simply deny the write as the page will remain dirty which will cause the MPW to trigger again later 
		// for a *cached* write the Cc memory maps the file and copies the user data into the mapping 
		// if someone else then comes and memory maps the file the mapping will use the same physical pages backing the Cc mapping 
		// when flushing dirty pages the os builds an MDL to describe the same physical pages (again, same physical pages Cc uses for the file)
		// knowing that , modifying the buffer directly will cause everyone with the mapping to see the changes 
		// take encryption drivers for example, this is an issue as the intent is to only protect the data on disk 
		// in this case , we don't mind manipulating the buffer directly, as otherwise the ransomware will just corrupt the data anyway...

		if (processes::CheckForMaliciousSectionOwner(&FileContx->FileName))
		{
			SIZE_T BytesToWrite = (WriteParams.Length >= FileSize) ? FileSize : WriteParams.Length;
			PVOID  OverwrittenDiskContent = (PVOID)((ULONG_PTR)DiskContent + WriteParams.ByteOffset.QuadPart);
			__try
			{
				__try
				{
					
					RtlCopyMemory(DataToBeWritten,OverwrittenDiskContent, BytesToWrite);
					DbgPrint("[*] prevented modification to %wZ by malicious process \n", FileContx->FileName);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("[*] exception in attempt to prevent modification to %wZ by malicious process\n",FileContx->FileName);
				}
			}
			__finally
			{
				FltReleaseContext(FileContx);
				ExFreePoolWithTag(DiskContent, TAG);
				ExFreePoolWithTag(DataCopy, TAG);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
		}
```

#### RansomGuard against Maze 
RansomGuard deals with Maze comfortably , for a deatiled description of Maze check Sophos's blogpost out :  [Sophos's post](https://news.sophos.com/en-us/2020/05/12/maze-ransomware-1-year-counting/ ). <br/>
* 11 files encrypted , 10 of which RansomGuard restored
* Maze successfully killed 
* Debug output :
  
```yaml

00000481	257.80279541	[*] R/W section is created for \Device\HarddiskVolume3\$Recycle.Bin\S-1-5-21-1519848365-1663756913-3822597310-1001\$RAL6GT6\htb-job1 - Copy.png		
00000484	258.02233887	[*] backed up htb-job1 - Copy.png	
00000485	258.02896118	[*] \Device\HarddiskVolume3\$Recycle.Bin\S-1-5-21-1519848365-1663756913-3822597310-1001\$RAL6GT6\htb-job1 - Copy.png encrypted by 552	
00000486	258.03894043	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\Maze.exe -> 1		
00000516	267.57147217	[*] R/W section is created for \Device\HarddiskVolume3\RansomGuard_User_Restore\htb-job1 - Copy.png		
00000521	267.90890503	[*] backed up htb-job1 - Copy.png	
00000522	267.91683960	[*] \Device\HarddiskVolume3\RansomGuard_User_Restore\htb-job1 - Copy.png encrypted by 552	
00000523	267.96432495	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\Maze.exe -> 2	
00000588	295.95721436	[*] R/W section is created for \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Crypto\Keys\de7cf8a7901d2ad13e5c67c29e5d1662_						162686e5-3e74-454e-a51b-1e4ebdadf298	
00000592	296.29370117	[*] backed up de7cf8a7901d2ad13e5c67c29e5d1662_162686e5-3e74-454e-a51b-1e4ebdadf298	
00000593	296.30459595	[*] \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Crypto\Keys\de7cf8a7901d2ad13e5c67c29e5d1662_162686e5-3e74-454e-a51b-1e4ebdadf298 					encrypted by 552	
00000594	296.31512451	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\Maze.exe -> 3	
00000598	297.99856567	[*] backed up de7cf8a7901d2ad13e5c67c29e5d1662_162686e5-3e74-454e-a51b-1e4ebdadf298	
00000599	298.00854492	[*] \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Crypto\Keys\de7cf8a7901d2ad13e5c67c29e5d1662_162686e5-3e74-454e-a51b-1e4ebdadf298 					encrypted by mapped page writer	
00000600	298.02206421	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\Maze.exe -> 4	
00000649	313.89920044	[*] R/W section is created for \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Protect\S-1-5-21-1519848365-1663756913-3822597310-1001\0ae5e0a7-afbf-4146-aeb8-916bbc5715e9	
00000650	313.94641113	[*] [\Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Protect\S-1-5-21-1519848365-1663756913-3822597310-1001\0ae5e0a7-afbf-4146-aeb8-916bbc5715e9] pre paging write 6421 predicted paging write 7570 diff 1150	
00000651	314.25094604	[*] [\Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Protect\S-1-5-21-1519848365-1663756913-3822597310-1001\0ae5e0a7-afbf-4146-aeb8-916bbc5715e9] pre paging write 5760 predicted paging write 7762 diff 2003	
00000652	314.37820435	[*] backed up 0ae5e0a7-afbf-4146-aeb8-916bbc5715e9	
00000653	314.38742065	[*] \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Protect\S-1-5-21-1519848365-1663756913-3822597310-1001\0ae5e0a7-afbf-4146-aeb8-916bbc5715e9 encrypted by mapped page writer	
00000654	314.40267944	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\Maze.exe -> 5	
00000700	328.47003174	[*] backed up CameraRoll.library-ms	
00000701	328.47637939	[*] \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Windows\Libraries\CameraRoll.library-ms encrypted by 552	
00000702	328.48638916	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\Maze.exe -> 6	
00000704	329.65780640	[*] R/W section is created for \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Windows\Libraries\Documents.library-ms	
00000709	329.95840454	[*] backed up Documents.library-ms	
00000710	329.96768188	[*] \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Windows\Libraries\Documents.library-ms encrypted by 552	
00000711	329.98110962	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\Maze.exe -> 7	
00000698	328.15954590	[*] R/W section is created for \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Windows\Libraries\CameraRoll.library-ms	
00000713	330.46475220	[*] backed up CameraRoll.library-ms	
00000714	330.47409058	[*] \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Windows\Libraries\CameraRoll.library-ms encrypted by mapped page writer	
00000715	330.48303223	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\Maze.exe -> 8	
00000718	330.91784668	[*] R/W section is created for \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Windows\Libraries\Music.library-ms	
00000721	331.42086792	[*] backed up Music.library-ms	
00000722	331.42776489	[*] \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Windows\Libraries\Music.library-ms encrypted by 552	
00000723	331.43615723	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\Maze.exe -> 9	
00000724	331.66406250	[*] backed up Documents.library-ms	
00000725	331.67065430	[*] \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Windows\Libraries\Documents.library-ms encrypted by mapped page writer	
00000726	331.68273926	[*] files encrypted by \Device\HarddiskVolume3\Users\dorge\Desktop\Maze.exe -> 10	

00000732	332.89422607	[*] prevented modification to \Device\HarddiskVolume3\Users\dorge\AppData\Roaming\Microsoft\Windows\Libraries\Music.library-ms by malicious process 	
00000734	333.01222278    [*] killed ransomware process! 
00000735	333.76620483	[*] waiting two minutes to remove 552 process entry	
```


## Filtering file deletions 
A file or directory is deleted when a deletion request is pending and the last user reference to the file is released (that is, the last ```IRP_MJ_CLEANUP``` is sent to the file system). A deletion request can be initiated in one of two ways : 
* ```IRP_MJ_CREATE``` with the ```DELETE_ON_CLOSE``` flag set.
* ```IRP_MJ_SET_INFORMATION``` with ```FileDispositionInformation/Ex``` passing ```FILE_DISPOSITION_INFORMATION``` structure with the ```DeleteFile``` boolean set to true.

There's an interesting twist to this, the delete disposition can also be reset by calling the same ```IRP_MJ_SET_INFORMATION``` request with the ```FileDispositionInformation``` information class with the ```DeleteFile``` member set to FALSE. This means that the file will not be deleted from the file system once the final handle is closed, cancelling the previous request to delete the file. This call (to set ```DeleteFile``` to FALSE) will be successful regardless of whether the file had a delete disposition set or not. In fact, one can call to set and reset the disposition many times and whoever called last to set the disposition to either true or false will win.<br/>
Since the delete disposition can also be manipulated from different handles , it must be a per stream flag , again looking at the FastFat source in ```FatSetDispositionInfo``` confirms  the flag is indeed part of the ```FCB```. (operations on the same on disk object share the same file control block, pointed by ```FileObject->FsContext```).

```cpp
SetFlag( Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE );
FileObject->DeletePending = TRUE;
```

But we already mentioned there's yet another way to reuqest a delete , ```IRP_MJ_CREATE``` with the ```DELETE_ON_CLOSE``` flag , looking at the FastFat source in ```FatCommonCreate``` : 

```cpp
            PCCB Ccb = (PCCB)FileObject->FsContext2;

            if (DeleteOnClose) {

                SetFlag( Ccb->Flags, CCB_FLAG_DELETE_ON_CLOSE );
            }
```

We can see that the flag is translated into a```CCB``` flag, ```CCB_FLAG_DELETE_ON_CLOSE```. The ```CCB``` is unique per FILE_OBJECT so basically the FILE_OBJECT remembers that it was opened with the ```FILE_DELETE_ON_CLOSE``` flag. The question is, where is the ```CCB_FLAG_DELETE_ON_CLOSE``` flag converted into ```FCB_STATE_DELETE_ON_CLOSE``` ? <br/>
A quick search shows this happens during ```IRP_MJ_CLEANUP``` , which has some noticable implications : 
* Since the  ```FCB``` flag isn't set an ```IRP_MJ_QUERY_INFORMATION``` request with the ```FileStandardInformation``` information class will not return the ```DeletePending``` flag even though the file is going to be deleted.
* Trying to set the ```DeleteFile``` flag to FALSE will have no effect since the ```FILE_DISPOSITION_INFORMATION``` structure only affects the ```FCB_STATE_DELETE_ON_CLOSE``` flag and not the ```CCB``` one.

One interesting issue we are going to face when tracking file deletes is the fact the NT I/O stack is asynchrnous and as such the order in which a minifilter sees requests is not necessarily the order in which the file system sees them. Consider two ```IRP_MJ_SET_INFORMATION``` requests with ```FileDispoisition``` once in which the ```DeleteFile``` flag is set to true and another to false.  Moreover , they are racing in a way that the filter sees both pre operation callbacks before it sees the post operation callback for either of them (in other words both requests are being processed by layers below the filter at the same time). When a filter sees these requests it might see the one that sets it to TRUE and then the one that sets it to FALSE and assume that the delete disposition was set and then reset and so the file won't be deleted. However, it's very possible that the file system will received the request that sets the delete disposition to FALSE before the one it sets it to TRUE and so it will delete the file. This is clearly not a frequent case but it can happen (e.g. a minifilter below us in the stack pended the request).<br/> 

Rewind the reason we are interested in deletes is the following sequence:

 






## Dealing with variation 3 (not implemented)


## Tests data agianst various ransomwares
