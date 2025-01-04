---
title:  "AudioGuard :  controlling microphone access on per-process basis"
date:   2024-10-30
tags: [posts]
excerpt: "controlling microphone access on per-process basis"
---

## Intro
Long-term surveillance hinges (among other things) on microphone capture and recording capabilities, serving as a cornerstone of persistent monitoring operations, whether state-sponsored or not. Threat actors can silently harvest sensitive intelligence from team meetings, voice chats, and  internal discussions as long as the endpoint has a microphone device connected to it, providing access to organizational insights. In this blogpost, our goal is to uncover the internals behind the audio subsystem on Windows, and design a protection solution with the capability of blocking microphone access, either entirley, or on a per-process basis!  

## Some KS terminology 
Whenever we open our webcam, activate our microphone or enable sound. The system needs to read or write related data such as your voice or captured images into RAM. Kernel Streaming (KS) refers to the Microsoft-provided services that support kernel-mode processing of streamed data.  KS serves as a standardized interface for multimedia devices, and aims to provide low latency and simplified multimedia driver development. Microsoft provides three multimedia class driver models: port class, stream class, and AVStream. These class drivers are implemented as export drivers (kernel-mode DLLs) in the system files portcls.sys, stream.sys, and ks.sys. the ```portcls.sys``` driver is what most hardware drivers for PCI and DMA-based audio devices based on. the port clsss driver supplies a set of port drivers that implement most of the generic kernel streaming (KS) filter functionality, it's essentially another abstraction on top of ```ks.sys``` making the job of driver devs easier.

### KS pins and filters 
Conceptually, a stream undergoes processing as it flows along a data path containing some number of processing nodes. A set of related nodes is grouped together to form a KS filter, which represents a more-or-less independent block of stream-processing functionality. More complex functions can be constructed in a modular way by cascading several filters together to form a filter graph. A KS filter is implemented as a kernel-mode KS object that encapsulates some number of related stream-processing callbacks, described by a [KSFILTER_DESCRIPTOR](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ks/ns-ks-_ksfilter_descriptor) structure. KS filters are connected together through their pins. A pin on an audio filter can be thought of as an audio jack. A client instantiates an input or output pin on a filter when the client needs to route a data stream into or out of that filter. Similarly to a ```KSFILTER```, a ```KSPIN``` is described by a [KSPIN_DESCRIPTOR](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ks/ns-ks-kspin_descriptor). For example, a filter that performs audio mixing might have one [pin factory](https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/pin-factories) that can instantiate a single output pin and a second pin factory that can instantiate several input pins. 

## The windows audio subsystem 
The audio architecture changed dramatically in the rewrite that was done in Vista. Technically, audio drivers do communicate through kernel streaming, but the graph typically contains only one filter. The graph is owned and operated by the Audio Engine process (Audiodg.exe) Client applications eventually get down to [WASAPI](https://learn.microsoft.com/en-us/windows/win32/coreaudio/wasapi) calls, which result in requests being sent to the Audio Engine through several layers of IPC. The Audio Engine then manages the communication with the device, not through ```IOCTL_KS_READ_STREAM``` (which is used for camera devices) but rather through a shared circular buffer, the Audio Engine writes and reads from this buffer without kernel involvement. This is why audio effects are now done by APOs (audio processing objects), which are COM DLLs that load in the Audio Engine process. Having said that, certian KS IOCTLs are still in use, we will discuss them in detail later on in the blogpost.

### UM Components - AudioSes.dll
As mentioned client applications eventually get down to WSAPI calls, namely through the use of the ```IAudioClient``` COM interface. ```AudioSes.dll``` is the in-process COM server that implements ```IAudioClient```. 

### UM Components - AudioEng.dll
The audio engine (```AudioEng.dll```) is loaded by the Audio Device Graph process (```Audiodg.exe```), it's responsible for:
* Mixing and processing of audio streams
* Owning the filter graph and loading APOs (Audio Processing Objects)

In addition, it handles communication with the kernel-mode counterpart of the audio subsystem whenever required, through ```AudioKSE.dll``` module. It's worth mentioning the Audio Device Graph was once a protected process, but at least from Windows 10 that is no more the case. 

### UM Components - AudioSrv.dll 
The audio service (```AudioSrv.dll```) loads in an instance of svchost, it's responsible for:
* Starting and controlling audio streams
* Implementing Windows policies for background audio playback, ducking, etc.

The audio service sits between ```AudioEng.dll``` and ```AudioSes.dll``` (client applications), and communicates with clients using LRPC over the following ALPC port. 

<img src="{{ site.url }}{{ site.baseurl }}/images/AudioClientRpcPort.png" alt="">

## The kernel side of the audio subsystem 
To better understand the kernel interaction within the audio subsystem, I wrote a generic plug & play upper filter that logs IRPs, and installed it for the media device class:

<img src="{{ site.url }}{{ site.baseurl }}/images/MedDesc.png" alt="">

> Despite it's misleading description, joysticks go into Human Interface Devices, and video capture devices typically go into Cameras.

Typically, the audio stack will be constructed from devices managed by ```ksthunk.sys```, ```HdAudio.sys``` and ```HdAudBus.sys```:
<img src="{{ site.url }}{{ site.baseurl }}/images/audio_devstack.png" alt="">

Upon restarting the system and running a sample audio recording application, we can examine our driver's output. 

> There are hundereds of IOCTLs in play, most of them related to [audio format negotiation](https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/audio-data-formats)
> 
> Nevertheless, after some reserach - these are the requests I found to be worth mentioning

```yaml
IRP_MJ_CREATE -> ...\.e.m.i.c.i.n.w.a.v.e.
* Corresponding to a KsOpenDefaultDevice call

IOCTL_KS_PROPERTY -> KSPROPERTY_PIN 

IRP_MJ_CREATE -> <KSNAME_Pin><KSPIN_CONNECT><KSDATAFORMAT> 

IOCTL_KS_PROPERTY -> KSPROPERTY_CONNECTION_STATE -> KSSTATE_ACQUIRE (Set)

IOCTL_KS_PROPERTY -> KSPROPERTY_CONNECTION_STATE -> KSSTATE_PAUSE (Set)

IOCTL_KS_PROPERTY -> KSPROPERTY_CONNECTION_STATE -> KSSTATE_RUN (Set)
***
Recording Starts
***

...

***
Recording Ends
***

IOCTL_KS_PROPERTY -> KSPROPERTY_CONNECTION_STATE -> KSSTATE_ACQUIRE (Set)

IOCTL_KS_PROPERTY -> KSPROPERTY_CONNECTION_STATE -> KSSTATE_STOP (Set)
```
As expected, those IRPs are being generated from the audio engine (through ```AudioKSE.dll```) in the audiodg process.
<img src="{{ site.url }}{{ site.baseurl }}/images/AudioKSEStack.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/AudioKSE_Process.png" alt="">


## IRP_MJ_CREATE for KSPIN 
Upon obtaining a handle to a ```KSFILTER``` object (e.g. via a ```KsOpenDefualtDevice``` call), the audio engine initiates another create operation targeted at one of the filter's pins. Bizarrely, as disovered by [Michael Maltsev](https://x.com/m417z) in his camera stack focused research, the file name in the ```IRP_MJ_CREATE``` operation for the pin begins with the ```KSNAME_Pin``` GUID and is followed by a [KSPIN_CONNECT](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ks/ns-ks-kspin_connect) structure that contains the pin id, and a binary [KSDATAFORMAT](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ks/ns-ks-ksdataformat) structure that defines the format to be used. More about the avaliable audio formats [here](https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/audio-data-formats).

## IOCTL_KS_PROPERTY 
```IOCTL_KS_PROPERTY``` is used to get or set properties, or to determine the properties supported by a KS object. The format of an ```IOCTL_KS_PROPERTY``` request conssists of a property descriptor, passed in the input buffer, and a property value - passed over the output buffer. The type of the descriptor is mostly:

<img src="{{ site.url }}{{ site.baseurl }}/images/KsDescFormat.png" alt="">

*  ```PKSIDENTIFIER->Set``` points to a [property set](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/avstream-property-sets)
*  ```PKSIDENTIFIER->Id``` points to the specific property within the specefied property set

Of course, the type of the property value varies and depends on the property. 

the property descriptor and value types are often documented via a usage summary table in the MSDN page for the property.
<img src="{{ site.url }}{{ site.baseurl }}/images/UsageTable.png" alt="">
> KSPROPERTY and KSIDENTIFIER are aliases, and have the same definition.

As indicated by our driver's log, the property ```KSSTATE_RUN``` of the ```KSPROPERTY_CONNECTION_STATE``` property set is set to start a recording. On the other hand, to stop the recording one would have to set ```KSSTATE_STOP```.

As with all KS IOCTLs, ```IOCTL_KS_PROPERTY``` is defined as ```METHOD_NEITHER```, meaning data is passed via raw user addresses accessible only in the caller's context. 

## Blocking microphone access 
AVs allow the user to conifgure the type of protection applied on the microphone,typically under the privacy protection settings.
Let's start by implementing the most robust configuration - blocking any attempt to record our microphone.
A straightforward approach is to simply block incoming ```IOCTL_KS_PROPERTY``` IRPs setting the ```KSSTATE_RUN``` property of the ```KSPROPERTY_CONNECTION_STATE``` property set. However, to be able to support other configuration options in the future, a better design would be to notify a UM service whenever such request occurs, using the [inverted call model](https://www.osronline.com/article.cfm%5Eid=94.htm#:~:text=Driver%20writers%20often%20ask%20whether%20or%20not%20a,that%20can%20be%20used%20to%20achieve%20similar%20functionality.)). Next, we can place the IRP in a [cancel safe queue](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/cancel-safe-irp-queues), wait for a response from the service indicating the way the driver should handle the request, extract it from the queue and complete it accordingly. Code to handle an ```IOCTL_KS_PROPERTY``` in the said design would look like the following:
```cpp
bool filter::KsPropertyHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IoStackLocation)
{
    GUID PropertysetConnection = GUID_PROPSETID_Connection;
    ULONG OutputBufferLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;

    if (!InputBufferLength || !OutputBufferLength)
        return AUDGUARD_COMPLETE;

    PVOID InputBuffer = IoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
    PVOID OutputBuffer = Irp->UserBuffer;

    // IOCTL_KS_PROPERTY is method neither, we are provided with the user addresses as is  
    // since AudioGuard is attached at the top of the stack we can access these buffers directly 
    // must be done in a try except as the buffer might get freed any time by the user thread 

    __try
    {

        ProbeForRead(InputBuffer, InputBufferLength, sizeof(UCHAR));

        PKSIDENTIFIER KsIdentifier = reinterpret_cast<PKSIDENTIFIER>(InputBuffer);

        if (IsEqualGUID(KsIdentifier->Set, PropertysetConnection))
        {

            if (KsIdentifier->Id == KSPROPERTY_CONNECTION_STATE && KsIdentifier->Flags == KSPROPERTY_TYPE_SET)
            {
                KSSTATE KsStatePtr = *reinterpret_cast<PKSSTATE>(OutputBuffer);

                switch (KsStatePtr)
                {
                case KSSTATE_STOP:
                    DbgPrint("[*] AudioGuard :: request to set KSSTATE_STOP\n");
                    break;

                case KSSTATE_ACQUIRE:
                    DbgPrint("[*] AudioGuard :: request to set KSSTATE_ACQUIRE\n");
                    break;

                case KSSTATE_PAUSE:
                    DbgPrint("[*] AudioGuard :: request to set KSSTATE_PAUSE\n");
                    break;

                    // sent on capture start!
                    // handle it by placing the IRP in an IRP queue and prompt the user asynchronously 
                    // since we are not going to touch the buffers anymore we don't have to map them
                    // in case the user allows processing to proceed we will call IofCallDriver in an apc, allowing ksthunk to map these user addresses

                case KSSTATE_RUN:
                    DbgPrint("[*] AudioGuard :: request to set KSSTATE_RUN\n");

                    // notify service of KS request
                    pCsqIrpQueue ClientIrpQueue = reinterpret_cast<pCsqIrpQueue>(globals::ClientDeviceObject->DeviceExtension);
                    PIRP ClientIrp = IoCsqRemoveNextIrp(&ClientIrpQueue->CsqObject, nullptr);
                    if (!ClientIrp)
                    {
                        return AUDGUARD_COMPLETE;
                    }


                    Irp->Tail.Overlay.DriverContext[0] = DeviceObject;

                    // IOCsqInsertIrp marks the IRP as pending 
                    IoCsqInsertIrp(&globals::g_pKsPropertyQueue->CsqObject, Irp, nullptr);

                    ClientIrp->IoStatus.Status = STATUS_SUCCESS;
                    ClientIrp->IoStatus.Information = 0;
                    IoCompleteRequest(ClientIrp, IO_NO_INCREMENT);

                    return AUDGUARD_PEND;
                }

            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[*] AudioGuard :: exception accessing buffer in ksproperty handler\n");
    }

    return AUDGUARD_COMPLETE;
}
```
And to handle the response from the service:
```cpp
NTSTATUS client::device_control(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
...
	case IOCTL_AUDGUARD_USER_DIALOG:

		KsIrp = IoCsqRemoveNextIrp(&globals::g_pKsPropertyQueue->CsqObject, nullptr);
		if (!KsIrp)
			break;

		ProtectionServiceConfig = *reinterpret_cast<int*>(Irp->AssociatedIrp.SystemBuffer);

		// complete the previously pended IOCTL_KS_PROPERTY 
		// we have to do it from the caller's context since ksthunk (below us) will try to map user addresses
		if (apc::queue_completion_kernel_apc(KsIrp, ProtectionServiceConfig))
			status = STATUS_SUCCESS;
...
}
```

## Completion thread context
KS IOCTLs are ```METHOD_NEITHER```, remember? Once we decide to pend a KS IOCTL, we have to ensure we don't complete it in an arbitrary thread context, as ksthunk, the driver below us in the stack, will try to map and access the provided user buffers  which are valid only in the caller's context. That means when completing the previously pended IRP, we must do that through queueing an apc to the 
caller thread.
```cpp

void apc::normal_routine(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	pApcContext ApcContx = reinterpret_cast<pApcContext>(NormalContext);
	PDEVICE_OBJECT FilterDeviceObject = reinterpret_cast<PDEVICE_OBJECT>(ApcContx->Irp->Tail.Overlay.DriverContext[0]);
	filter::pDeviceExtension DevExt = reinterpret_cast<filter::pDeviceExtension>(FilterDeviceObject->DeviceExtension);

	int ProtectionServiceConfig = ApcContx->ProtectionServiceConfig;

	// if service is configured to block all access complete with status denied  
	if (ProtectionServiceConfig == AUDGUARD_BLOCK_MIC_ACCESS)
	{
		DbgPrint("[*] AudioGuard :: completing IOCTL_KS_PROPERTY IRP with access denied!\n");
		ApcContx->Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		ApcContx->Irp->IoStatus.Information = 0;
		IofCompleteRequest(ApcContx->Irp, IO_NO_INCREMENT);
	}

	// otherwise pass the request down 
	else
	{
		DbgPrint("[*] AudioGuard :: passing IOCTL_KS_PROPERTY IRP down the audio stack!\n");
		IoSkipCurrentIrpStackLocation(ApcContx->Irp);
		IofCallDriver(DevExt->LowerDeviceObject, ApcContx->Irp);
	}

	IoReleaseRemoveLock(&DevExt->RemoveLock, ApcContx->Irp);
	ExFreePoolWithTag(ApcContx, TAG);

}
```

## More work to be done  
The ```IOCTL_KS_PROPERTY``` - ```KSSTATE_RUN``` IRP is sent from the audio engine, thus all requests seem as if they were originated from it. We need a to find  way to construct context back to the recording process. Let's take a closer look at the subsystem's components, with our driver involved: 
<img src="{{ site.url }}{{ site.baseurl }}/images/AudioGuardFlow.png" alt="">

## IAudioClient->Start under the hood
The following is a sample code for using the ```IAudioClient``` interface to record input from a connected microphone and save it to a .wav file:
```cpp
    hr = CoInitializeEx(NULL, COINIT_SPEED_OVER_MEMORY);
    EXIT_ON_ERROR(hr)

        hr = CoCreateInstance(
            __uuidof(MMDeviceEnumerator), NULL,
            CLSCTX_ALL, __uuidof(IMMDeviceEnumerator),
            (void**)&pEnumerator);
    EXIT_ON_ERROR(hr)

        hr = pEnumerator->GetDefaultAudioEndpoint(
            eCapture, eConsole, &pDevice);
    EXIT_ON_ERROR(hr)

        hr = pDevice->Activate(
            __uuidof(IAudioClient), CLSCTX_ALL,
            NULL, (void**)&pAudioClient);
    EXIT_ON_ERROR(hr)

        hr = pAudioClient->GetMixFormat(&pwfx);
    EXIT_ON_ERROR(hr)

        // Adjust wave header with audio format
        waveHeader.numChannels = pwfx->nChannels;
    waveHeader.sampleRate = pwfx->nSamplesPerSec;
    waveHeader.byteRate = pwfx->nAvgBytesPerSec;
    waveHeader.blockAlign = pwfx->nBlockAlign;
    waveHeader.bitsPerSample = pwfx->wBitsPerSample;

  
    hr = pAudioClient->Initialize(
        AUDCLNT_SHAREMODE_SHARED,
        0,
        hnsRequestedDuration,
        0,
        pwfx,
        NULL);
    EXIT_ON_ERROR(hr)

        hr = pAudioClient->GetBufferSize(&bufferFrameCount);
    EXIT_ON_ERROR(hr)

        hr = pAudioClient->GetService(
            __uuidof(IAudioCaptureClient),
            (void**)&pCaptureClient);
    EXIT_ON_ERROR(hr)

    // Start capturing 
        hr = pAudioClient->Start();
    EXIT_ON_ERROR(hr)

        // Write wave header to output file
        outFile.write(reinterpret_cast<char*>(&waveHeader), sizeof(waveHeader));

    // Record for 1 minute 
    for (int i = 0; i < 60; i++) {
        Sleep(1000); // Wait for 1 second

        hr = pCaptureClient->GetNextPacketSize(&packetLength);
        EXIT_ON_ERROR(hr)

            while (packetLength != 0) {
                hr = pCaptureClient->GetBuffer(
                    &pData,
                    &numFramesAvailable,
                    &flags, NULL, NULL);
                EXIT_ON_ERROR(hr)

                    if (flags & AUDCLNT_BUFFERFLAGS_SILENT) {
                        pData = NULL;  // Tell CopyData to write silence.
                    }

                // Only write if pData is not NULL
                if (pData != NULL) {
                    outFile.write(reinterpret_cast<char*>(pData),
                        numFramesAvailable * pwfx->nBlockAlign);
                    waveHeader.dataSize += numFramesAvailable * pwfx->nBlockAlign;
                }

                hr = pCaptureClient->ReleaseBuffer(numFramesAvailable);
                EXIT_ON_ERROR(hr)

                    hr = pCaptureClient->GetNextPacketSize(&packetLength);
                EXIT_ON_ERROR(hr)
            }
    }
// Stop capturing 
    hr = pAudioClient->Stop();
    EXIT_ON_ERROR(hr)

        Exit:
    // Update chunk size in wave header
    waveHeader.chunkSize = waveHeader.dataSize + 36;

    // Rewrite wave header to output file with updated chunk and data size
    outFile.seekp(0, std::ios::beg);
    outFile.write(reinterpret_cast<char*>(&waveHeader), sizeof(waveHeader));
```

The method of interest is ```pAudioClient->Start()```, which as the name suggests - starts the audio recording by streaming data between the endpoint buffer and the audio engine. under the hood, the method invokes the ```AudioSrv!AudioServerStartStream``` function over LRPC:

<img src="{{ site.url }}{{ site.baseurl }}/images/audiorpc2.png" alt="">
<img src="{{ site.url }}{{ site.baseurl }}/images/audiorpc1.png" alt="">

Dereferencing the ```MIDL_STUB_DESC``` structure passed to ```NdrClientCall3``` we can extract the RPC interface UUID: 

<img src="{{ site.url }}{{ site.baseurl }}/images/audiorpc3.png" alt="">

Using RPCView, we find out the RPC interface name is AudioClientRpc, Exported by ```AudioSrv.dll```.

<img src="{{ site.url }}{{ site.baseurl }}/images/audiorpc4.png" alt="">

Specifically, procnum 8 is mapped to the ```AudioSrv!AudioServerStartStream``` function as said before.

We can hook RPC here to construct context, but for obvious reasons monitoring from the process recording the audio, where the attacker has already gained code execution, is not ideal. So we dig deeper.
Statically reversing ```AudioSrv!AudioServerStartStream``` reveals a call to ```RtlPublishWnfStateData```

<img src="{{ site.url }}{{ site.baseurl }}/images/AudioServerWnfCallStatic.png" alt="">

For those unfamiliar with WNF, I highly recommend you check out Alex Ionescu's [black hat conference](https://www.youtube.com/watch?v=MybmgE95weo&t=1075s) on the topic. In a nutshell, WNF is a notification system where processes can subscribe and publish events without the need for other processes to be there. In the snippet above, the audio service publishes an ```WNF_AUDC_CAPTURE``` event, indicating a process has started / stopped capturing audio. By attaching to the audio service, placing a breakpoint on ```ntdll!RtlPublishWnfStateData``` and running our audio recording sample we can confirm that is indeed the case. 

<img src="{{ site.url }}{{ site.baseurl }}/images/RtlPublishWnfStateData_stack.png" alt="">

We can be called whenever a process is starting to capture audio, cool! but does WNF tell us which process it is? 
let's inspect the data passed by the publisher 

<img src="{{ site.url }}{{ site.baseurl }}/images/RtlPublishWnfStateData_params2.png" alt="">

In the 4 bytes marked in blue we find the number of processes currently using the microphone, and in the byte marked in yellow we find the process id of our audio recording process, so we can write the following WNF callback
```cpp
NTSTATUS wnf::Callback(PWNF_SUBSCRIPTION Subscription, PWNF_STATE_NAME StateName, ULONG SubscribedEventSet, WNF_CHANGE_STAMP ChangeStamp, PWNF_TYPE_ID TypeId, PVOID CallbackContext)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG BufSize = 0;
    PVOID pStateData = nullptr;
    pAudioStateData AudioCaptureStateData = nullptr;
    WNF_CHANGE_STAMP changeStamp = 0;

    Status = ExQueryWnfStateData(Subscription, &changeStamp, NULL, &BufSize);
    if (Status == STATUS_BUFFER_TOO_SMALL)
    {
        pStateData = ExAllocatePoolWithTag(NonPagedPool, BufSize, TAG);
        if (!pStateData)
            return STATUS_UNSUCCESSFUL;

        Status = ExQueryWnfStateData(Subscription, &ChangeStamp, pStateData, &BufSize);
        if (NT_SUCCESS(Status))
        {
            AudioCaptureStateData = reinterpret_cast<pAudioStateData>(pStateData);
            for (int i = 0; i < AudioCaptureStateData->NumberOfEntries; i++)
            {
                DbgPrint("[*] AudioGuard :: Wnf :: process capturing audio -> 0x%x\n", AudioCaptureStateData->Entries[i]);
            }
        }
        ExFreePoolWithTag(pStateData, TAG);
    }
    return Status;
}
```

Is that it? can we combine WNF with the filtering of ```IOCTL_KS_PROPERTY``` - ```KSSTATE_RUN``` IRPs and selectively block / allow microphone access on a per process basis? No, not quite. Unfortunately the audio service publishes the WNF event only after the ```IOCTL_KS_PROPERTY``` - ```KSSTATE_RUN``` IRP has been completed, which renders WNF unusable. Having said that, the process id published by ```RtlPublishWnfStateData``` has to come from somewhere, if we can access it from within the audio service before the ```IOCTL_KS_PROPERTY``` - ```KSSTATE_RUN``` IRP is initiated, that's good news. 

## Tracing backwards from RtlPublishWnfStateData
```RtlPublishWnfStateData``` is called from ```AudioSrv!AudioServerStartStream```, let's start by inspecting it's parameters 

<img src="{{ site.url }}{{ site.baseurl }}/images/CvadServer.png" alt="">

We can see the first argument is a pointer to an object of type ```audiosrv!CVADServer```, one of it's fields contains the PID of the audio recording process (```0x3d30``` in this case). the ```audiosrv!CVADServer``` object is initialized in ```audiosrv!AudioServerInitialize_Internal``` which is called in a response to the initial client call to ```pAudioClient->Initialize```.
We need to identify where the PID is initialized to determine whether it can be trusted. For example, if the PID is provided by the client, it cannot be trusted. Reversing of the function reveals ```audiosrv!AudioServerInitialize_Internal``` constructs an object of type ```IAudioProcess```,and passes it to  ```AudioSrvPolicyManager!CApplicationManager::RpcGetProcess``` :

<img src="{{ site.url }}{{ site.baseurl }}/images/RpcGetProcess.png" alt="">

> CProcess is an object pointed by one of the fields of IAudioProcess

The pid is retrieved via ```RPCRT4!I_RpcBindingInqLocalClientPID```, used by ncalrpc servers to identify the client process id from the server context. 

<img src="{{ site.url }}{{ site.baseurl }}/images/RpcBindingLocalPid.png" alt="">

> LRPC requests are sent over ALPC, where each message delivered contains both the data and the ALPC protocol header, described by a ```PORT_MESSAGE``` structure. This header has a ```ClientId``` field, which has both senders PID and TID. Upon receiving an ALPC request the RPC runtime inside the server process saves these values in the ```RPC_BINDING_HANDLE``` object, where they can be retrieved from just like above!

The retrieved PID is then stored in the ```IAudioProcess``` object. Later on, the same ```IAudioProcess``` object is used to construct ```CVADServer```, explaining how the first argument to ```AudioServerStartStream``` is initialized.

<img src="{{ site.url }}{{ site.baseurl }}/images/CvadServerCtor.png" alt="">

Since we know the client pid is coming from the RPC runtime and is not directly controlled by client input, a runtime hook on ```AudioSrv!AudioServerStartStream``` is a valid option to construct context!
