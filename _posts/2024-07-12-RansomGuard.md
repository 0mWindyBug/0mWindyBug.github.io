---
title:  "RansomGuard :  an anti-ransomware filter driver"
date:   2024-07-12
tags: [posts]
excerpt: "Anti Ransomware minifilter driver"
---


## Intro
Ransomware is one of the most simple - yet significant threats facing organizations today.<br />
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

Why should we care ? it's important to keep caching in mind before we are moving on to designing our file-system filter. <br/>

## A few words regarding Paging I/O 
For paging reads , it means the page is being read via the demand paging mechanism, and rather than the virtual address of a buffer we are given an MDL that describes the newly allocated physical pages , the read is of course non cached as it must be satisifed from storage<br/>
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
For a detailed description regarding the various checks avaliable , visit - (OSR link).<br/>
Enabling verifier during the development process is extremley important for writing a quality driver, note that when writing a minifilter you should enable it for both your driver and the fltmgr. <br/>

## Detecting encryption 
We already mentioned entropy as a measure to identify encryption of data, what we also mentioned is the fact compressed data tends to have high entropy.<br/>
Based on statistical tests with a large set of files of different types, we came up with the following measurement, that takes into consideration the initial entropy of the file.<br/>
.... show is encrypted function...<br/>
We found 0.83 as the sweet spot value for the coefficient between detecting encrypted files and limiting false positives.<br/>
As we increase the value of the coefficient the difference between the initial entropy value and the final entropy value to be considered suspicious increases. <br/>

## Tracking & Evaluating file handles   
To identify encryption has taken place we need to collect two datapoints.<br/>
First, that represents the initial entropy of the contents of the file, and second that represents the entropy of the contents of the file after modifcation.<br/> 
There a few things to consider:<br/>
1. A file may be truncated when opened , consequently by the time our filter's post create is invoked the initial state of the file is lost.<br/>
2. A ransomware may initiate several writes using different byte offsets to modify different portions of the same file.<br/>
Considering #1, we will monitor file opens that may truncate the file, indicated by a CreateDisposition value of FILE_SUPERSEDE , FILE_OVERWRITE or FILE_OVERWRITE_IF. in such cases the initial state of the file is captured in pre create, otherwise it is captured when the first write occurs - in pre write.<br/>
Considering #2 , the post modification state of the file is captured whenever whenever IRP_MJ_CLEANUP is sent.<br/>
that is, whenever the last handle to a file object is closed (represents the usermode state), in contrast IRP_MJ_CLOSE is sent whenever the last reference is released from the file object (represents the system state). <br/>
Any I/O operations (excluding paging I/O , IRP_MJ_QUERY_INFORMATION and apparently reads) are illegal after cleanup has completed, so it's safe to assume the file will not be modified (again , excluding paging I/O - we will deal with that later)  after the handle is closed by the user, hence we are going to use post cleanup as our second datapoint.<br/>
The following diagram summerizes RansomGuard's design for evaluating operations across the same handle.<br/>
<img src="{{ site.url }}{{ site.baseurl }}/images/RansomGuardDesign.png" alt="">

Next , let's walkthrough each filter to elaborate on design decisions and the implemntation. <br/> 

### filters::PreCreate 
Generally speaking , the PreCreate filter is responsible to filter out any uninteresting I/O requests. For now , we are only interested in 
file opens for R/W from usermode (so yes , not filtering new files , altough that's going to change later on in the blogpost). <br/>
In addition , as we've discussed earlier this is our only chance to capture the initial state of truncated files , if the file might get truncated - we read the file , calculate it's entropy, backup it's contents in memory and pass it all to PostCreate.<br/>
Lastly , to enforce access restrictions :
* The restore directory is accessible only from kernel mode
* A process marked as malicious(ransomware) is blocked from any file-system access
<br/>
  
```cpp
FLT_PREOP_CALLBACK_STATUS
filters::PreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	UNREFERENCED_PARAMETER(CompletionContext);

	ULONG FileSize = 0;
	ULONG_PTR stackLow;
	ULONG_PTR stackHigh;
	NTSTATUS status;
	PFILE_OBJECT FileObject = Data->Iopb->TargetFileObject;

	// block any file-system access by malicious processes or to our restore directory 
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


	//  Stack file objects are never scanned
	IoGetStackLimits(&stackLow, &stackHigh);

	if (((ULONG_PTR)FileObject > stackLow) &&
		((ULONG_PTR)FileObject < stackHigh)) 
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	//  Directory opens don't need to be scanned.
	if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	//  Skip pre-rename operations which always open a directory.
	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	//  Skip paging files.
	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) 
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	//  Skip scanning DASD opens 
	if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) 
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// Skip kernel mode or non write requests
	const auto& params = Data->Iopb->Parameters.Create;
	if (Data->RequestorMode == KernelMode
		|| (params.SecurityContext->DesiredAccess & FILE_WRITE_DATA) == 0 )
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

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
Ignore some of these fields for now, they will make sense later. <br/>
Since we use a statistical logic to identify encryption , we set a threshold of encrypted by a process to which we consider it as ransomware, the ```EncryptedFiles``` counter is used for that matter. <br/>


#### per - filter description (what does it filter, role , code etc...) 

#### Test against WannaCry 

## Tracking & Evaluating Memory Mapped I/O 

#### Design diagram 

#### per - filter description (what does it filter, role , code etc...) 

#### Test against Maze 

## Filtering file deletions (not implemente)


## Dealing with variation 3 (not implemented)


## Tests data agianst various ransomwares
