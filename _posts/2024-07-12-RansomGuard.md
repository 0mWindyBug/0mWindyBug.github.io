---
title:  "RansomGuard :  an anti-ransomware filter driver"
date:   2024-07-12
tags: [posts]
excerpt: "Anti Ransomware minifilter driver"
---


## Intro
Ransomware is one of the most simple - yet significant threats facing organizations today.<br/>
Unsuprisingly, the rise and continuing development of ransomware led to a plentitude of research aimed at detecting and preventing it -  AV vendors , independent security reseachers and academies all proposing various solutions to mitigate the threat.<br /> 
Today's blogpost is going to walkthrough the  design of RansomGuard - a fun open source anti-ransomware filter driver we developed, as well as covering the required internals.<br />


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
The filter manager provides a level of abstraction allowing driver developers to invest more time into the actual logic of the filter rather than writing a body of "boiler plate" code - speaking of boiler plate code , writing a legacy file-system filter driver that ** does nothing ** can take up to nearly 6,000 lines of code. <br/>
The filter manager is essentially a comprehensive “framework” for writing file system filter drivers.<br/> The framework provides the one legacy file system filter driver necessary in the system (fltmgr.sys). <br/>
As I/O requests arrive at the filter  manager legacy filter Device Object, filter manager calls the minifilters using a call out model.<br/> After each minifilter processes the request, the filter manager then calls through to the next device object in the device stack. <br />
It's important to note that easy to write does not mean easy to design , which remains a fairly complex task with minifilters, of course - depending on the minifilter's task. Nevertheless it makes it possible to go from design to a working filter in weeks rather than months, which is great. <br />


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

Why do we care ? it's important to keep caching in mind before we are moving on to designing our file-system filter. <br/>

## A few words regarding Paging I/O 
Paging I/O is essentially a term used to describe I/O initiated by either the Mm or Cc. For paging reads , it means the page is being read via the demand paging mechanism, and rather than the virtual address of a buffer we are given an MDL that describes the newly allocated physical pages , the read is of course non cached as it must be satisifed from storage.<br/>
For paging writes , it means something within the Virtual Memory System (either Mm or Cc) is requesting that data within the given physical pages will be written back to storage by the file-system driver , much like with a paging read , to flush out dirty pages the O/S builds an MDL to describe the physical pages of the mapping and sends the non-cached, paging write<br/> 
Again , keep these in mind : ) 


## Ransomware variations 
We have to consider all the variants of the encryption process, as it can happen very differently. <br/>
The most popular variation is where
the files are opened in R/W, read and encrypted in place, closed, and then (optionally) renamed. <br/> Another option is memory mapping the files , from a ransomware prespective not only that it's faster,  it can be more evasive as the write is initiated by the system process rather than the malicious one. <br/> This trick alone was enough for Maze and other ransomware families to evade security solutions. <br/>
Yet another way could be creating a copy of the file with the new name , opened for W, the original file is read, its encrypted content is written inside and the original file is deleted.<br/>
Whilst there are other possiblities , we are going to tackle those 3 as they are (by far) the most commonly  implemented in ransomwares in the wild. <br/> 

## Driver Verifier 
Before starting to write our driver , let's talk about verifier briefly. <br/> Driver Verifier can subject Windows drivers to a variety of stresses and tests to find improper behavior. You can configure which tests to run, which allows you to put a driver through heavy stress loads and enforce edge cases. <br/>
For a detailed description regarding the various checks avaliable , visit [OSR's post](https://www.osronline.com/article.cfm%5Earticle=325.htm) .<br/>
Enabling verifier during the development process is extremley important for writing a quality driver, note that when writing a minifilter you should enable it for both your driver and the fltmgr. <br/>

## Detecting encryption 
We already mentioned entropy as a measure to identify encryption of data, what we also mentioned is the fact compressed data tends to have high entropy.<br/> To identify encryption has taken place we need to collect two datapoints. 
First, that represents the initial entropy of the contents of the file, and second that represents the entropy of the contents of the file after modifcation.<br/> 
Based on statistical tests with a large set of files of different types, we came up with the following measurement, that takes into consideration the initial entropy of the file.<br/>

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
Considering #1, we will monitor file opens that may truncate the file, indicated by a CreateDisposition value of FILE_SUPERSEDE , FILE_OVERWRITE or FILE_OVERWRITE_IF. in such cases the initial state of the file is captured in pre create, otherwise it is captured when the first write occurs - in pre write.<br/>
Considering #2 , the post modification state of the file is captured whenever whenever IRP_MJ_CLEANUP is sent.<br/>
that is, whenever the last handle to a file object is closed (represents the usermode state), in contrast IRP_MJ_CLOSE is sent whenever the last reference is released from the file object (represents the system state). <br/>
Any I/O operations (excluding paging I/O , IRP_MJ_QUERY_INFORMATION and apparently reads) are illegal after cleanup has completed, so it's safe to assume the file will not be modified (again , excluding paging I/O - we will deal with that later)  after the handle is closed by the user, hence we are going to use post cleanup as our second datapoint.<br/>
The following diagram summerizes RansomGuard's design for evaluating operations across the same handle.<br/>
<img src="{{ site.url }}{{ site.baseurl }}/images/RansomGuardDesign.png" alt="">

Next , let's walkthrough each filter.<br/> 
For the full implemntation of the filters : https://github.com/0mWindyBug/RansomGuard/blob/main/RansomGuardBeta/RansomGuard/filters.cpp

### PreCreate 
Generally speaking , the PreCreate filter is responsible to filter out any uninteresting I/O requests. For now , we are only interested in 
file opens for R/W ,  from usermode (so yes , not filtering new files , altough that's going to change later on in the blogpost). <br/>
In addition , as we've discussed earlier this is our only chance to capture the initial state of truncated files , if the file might get truncated - we read the file , calculate it's entropy, backup it's contents in memory and pass it all to PostCreate.<br/>
Lastly , we enforce access restrictions : <br/>
* The restore directory is accessible only from kernel mode.
  - The user can connect to RansomGuard's filter port and issue a control to copy the files to a user-accesible location. <br/>
* A process marked as malicious(ransomware) is blocked from any file-system access.
<br/>

Enforcing file-system access restrictions : 
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
Not interested in requests from kernel mode or not for writing : 
```cpp
	// Skip kernel mode or non write requests
	const auto& params = Data->Iopb->Parameters.Create;
	if (Data->RequestorMode == KernelMode
		|| (params.SecurityContext->DesiredAccess & FILE_WRITE_DATA) == 0 )
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
```
Dealing with TRUNCATE_EXISTING opens : 
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
Here, if the file is not new (for now) and if the file-system supports FileObject contexts for the given operation(not supported in the paging I/O path) -  we initialize our FileObject context structure :

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
and attach it to the FileObject , nothing complex.<br/>

```cpp
FLT_POSTOP_CALLBACK_STATUS
filters::PostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)

{

	pCreateCompletionContext PreCreateInfo = (pCreateCompletionContext)CompletionContext;

	if (Flags & FLTFL_POST_OPERATION_DRAINING || !FltSupportsStreamHandleContexts(FltObjects->FileObject) || Data->IoStatus.Information == FILE_DOES_NOT_EXIST)
	{
		if (PreCreateInfo->SavedContent)
			ExFreePoolWithTag(PreCreateInfo->OriginalContent,TAG);

		FltFreePoolAlignedWithTag(FltObjects->Instance, CompletionContext, TAG);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	const auto& params = Data->Iopb->Parameters.Create;


	pHandleContext HandleContx = nullptr;
	NTSTATUS status = FltAllocateContext(FltObjects->Filter, FLT_STREAMHANDLE_CONTEXT, sizeof(HandleContext), NonPagedPool, reinterpret_cast<PFLT_CONTEXT*>(&HandleContx));
	if (!NT_SUCCESS(status))
	{
		if (PreCreateInfo->SavedContent)
			ExFreePoolWithTag(PreCreateInfo->OriginalContent, TAG);
		FltFreePoolAlignedWithTag(FltObjects->Instance, CompletionContext, TAG);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	// init context
	HandleContx->Instance = FltObjects->Instance;
	HandleContx->Filter = FltObjects->Filter;
	HandleContx->RequestorPid  = FltGetRequestorProcessId(Data);
	HandleContx->PostEntropy = INVALID_ENTROPY;
	HandleContx->PreEntropy = INVALID_ENTROPY;
	HandleContx->OriginalContent = nullptr;
	HandleContx->InitialFileSize = 0;
	HandleContx->FinalComponent.Buffer = nullptr;
	HandleContx->FileName.Buffer = nullptr;
	HandleContx->WriteOccured = false;
	HandleContx->SavedContent = PreCreateInfo->SavedContent;

	// if entropy was already calculated modify the default context 
	if (PreCreateInfo->CalculatedEntropy)
	{
		HandleContx->WriteOccured = true; 
		HandleContx->PreEntropy = PreCreateInfo->PreEntropy;
	}
	if (PreCreateInfo->SavedContent)
	{
		HandleContx->OriginalContent = PreCreateInfo->OriginalContent;
		HandleContx->InitialFileSize = PreCreateInfo->InitialFileSize;
	}

	// all pre create info has been moved to the handle context
	FltFreePoolAlignedWithTag(FltObjects->Instance, CompletionContext, TAG);

	FilterFileNameInformation FileNameInfo(Data);
	PFLT_FILE_NAME_INFORMATION NameInformation = FileNameInfo.Get();
	
	if (!NameInformation)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	HandleContx->FileName.Length = NameInformation->Name.Length;
	HandleContx->FileName.MaximumLength = NameInformation->Name.MaximumLength;
	if (NameInformation->Name.MaximumLength <= 0)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	HandleContx->FileName.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, HandleContx->FileName.MaximumLength, TAG);
	if (!HandleContx->FileName.Buffer)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	
	PUNICODE_STRING FileName = &NameInformation->Name;
	if (!FileName || !FileName->Buffer)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	RtlCopyUnicodeString(&(HandleContx->FileName), FileName);

	HandleContx->FinalComponent.Length = NameInformation->FinalComponent.Length;
	HandleContx->FinalComponent.MaximumLength = NameInformation->FinalComponent.MaximumLength;
	if (NameInformation->FinalComponent.MaximumLength <= 0)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	HandleContx->FinalComponent.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, HandleContx->FinalComponent.MaximumLength, TAG);
	if (!HandleContx->FinalComponent.Buffer)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	PUNICODE_STRING FinalComponent = &NameInformation->FinalComponent;
	if (!FinalComponent || !FinalComponent->Buffer)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	RtlCopyUnicodeString(&(HandleContx->FinalComponent), &NameInformation->FinalComponent);
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
If the FileObject is monitored (has a context attached to it) , and if it's the first write using the FileObject , capture the initial state of the file.<br/>

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
At this point the file cannot be modified using the same handle , due to IRQL restrictions capturing the second datapoint must be deferred to a worker thread, this is done by returning FLT_STATUS_MORE_PROCESSING_REQUIRED.<br/>

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

Knowing WannaCry follows the CreateFile -> ReadFile -> WriteFile -> CloseFile sequence , lets's test what we have so far against it!


## Filtering Memory Mapped I/O 
Usage of memory mapped files to perform the encryption becomes more and more common around ransomware families, which makes it harder for behavior based anti-ransomware solutions to keep track of what is going on, as mentioned this is due to the nature of memory mapped I/O.<br/>
<img src="{{ site.url }}{{ site.baseurl }}/images/RansomSequence2.png" alt="">

A file mapping is essentially a section object , with CreateFileMapping being a wrapper around NtCreateSection.<br/>
To write to a mapped file , an application maps a view of the file to the process and operates on the view's pages directly, as a result the corresponding PTEs are marked as dirty , when the virtual address range is flushed or unmapped the dirty PTE bit is "pushed out" to the PFN (i.e. the Modified bit gets set). Mofidied PFNs are written out back to storage asynchrnously by one of the page writers , for file backed sections by the mapped page writer , and for pagefile backed sections by the modified page writer.<br/>

From the ransomware perspective this is great , the actual write to the file seems as if it was originated from the system process, it can even happen after the process is terminated , and since the ransomware process itself only interacts with memory rather than disk , it's also much faster.<br/>
Our goal is to be able not only to detect those mapped page writer encryptions , but to be able to pinpoint back at the malicious process behind it.<br/>

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
To connect between a mapped page writer write and the process that memory mapped the file , we have to monitor the creation of section objects.<br/> The heuristic idea is to assume any process that created a R/W section object for the file might be the one that modified the mapping and triggered the asynchrnous write, that means , whenever our minifilter sees a mapped page writer encryption , we will traverse each process and check if it ever created a R/W section for file in question , if so , it's ```EncryptedFiles``` counter will be increased.<br/> The odds for two different processes (one being a ransomware and the other being legitimiate) , to create R/W section objects for the same X number of files , and for those X number of files to also get encrypted are very slim to say the least , and so os is the risk for false positives.<br/>

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
Next , we are going to check if the file has a file context attached to it , as we are only interested in noncached paging writes to files that have beem previously mapped by UM processes.<br/>
```cpp
pFileContext FileContx;

		// if there's a file context for the file 
		status = FltGetFileContext(FltObjects->Instance, FltObjects->FileObject, reinterpret_cast<PFLT_CONTEXT*>(&FileContx));
		if (!NT_SUCCESS(status))
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
```
Since the mapped page write only initiates one write , we can reliably capture both of our datapoints already in pre write, we know about the state of the file before the write and we know what is going to be written.<br/>
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
If the oepration is synchrnous, business as usual as we are in the caller's context. otherwise we call ```processes::UpdateEncryptedFilesAsync``` in which we increment the ```EncryptedFiles``` counter of any process that previously created a R/W section object for the encrypted file.<br/>

Theortically , there's a chance for a process to modify thousands of file mappings and terminate before the mapped page writer have been activated. When terminated , our process notify routine is invoked and the process structure is freed - we lose all tracking information we had on that process, to handle it , if the process terminated has created more than a threshold number of R/W sections , it's removal from the list is deffered to a dedicated system thread : 
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
As mentioned a process may be able to modify a large number of views before the mapped page writer activates. We can't prevent those modifications by killing the process , the paging writes have already been "scheduled" as the PTEs are marked as dirty. <br/> Once we know a ransomware is executing, and is using memory mapped I/O to encrypt files, ideally we'd like to prevent any modification to a file that is backed by a R/W section created by a process we classify as ransomware.<br/> We cant block the write (i.e. by returning access denied and FLT_PREOP_COMPLETE) as in such case  the PFN will remain modified - inevtibaly causing the mapped page writer to trigger again.
One option could be to lie and "successfully" complete the IRP :

```cpp
Data->Iosb.Status = STATUS_SUCCESS;
Data->Iosb.Information = Data->Iopb->Parameters.Write.Length;
return FLT_PREOP_COMPLETE
```
Whilst it will indeed prevent the modification, it can lead to major cache coherncey issues eventually causing applications to fail and potentially the machine to crash.<br/>


#### Test against Maze 

## Filtering file deletions (not implemente)


## Dealing with variation 3 (not implemented)


## Tests data agianst various ransomwares
