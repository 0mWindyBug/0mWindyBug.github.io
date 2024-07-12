---
title:  "Hardening the Windows kernel by monitoring driver loading"
date:   2024-01-13
tags: [posts]
excerpt: "A POC project that hardens the Windows kernel by blocking drivers that appear in vulnerable or malicious driver databases"
---
Introduction
---
Privilege escalation exploits are nothing new. Typically taking the form of UAC bypasses, these exploits have been utilized by attackers to execute code 
with the capability to significantly alter a user's computer and gain access to more sensitive parts of the operating system.

However, administrative privileges are not the highest in the Windows operating system; 
the actual highest privilege is NT Authority\System. This privilege level is virtually limitless and is what all kernel drivers run as.

This is one of the reasons that any important program that requires performing system-wide tasks might load a kernel driver,
like Sysmon and any AV or EDR systems for example. 

But there is another advantage which is the kind of APIs
that are accessible to you, allowing you to register callbacks and notify routines that can be used to monitor events and execute code system-wide,
This for example allows monitoring of every process and thread creation, file read and writes you can monitor the creation
of process handles and modify them which is often done to protect user-mode processes from termination
or dumping. These are just some examples but the possibilities are near limitless.


Kernel defensive mechanism - DSE
---
Running code inside the Windows kernel is undoubtedly a powerful capability, which is why when Microsoft first released Windows Vista, 
it also introduced DSE. Driver Signature Enforcement or DSE, is a security feature that only allows drivers signed by Microsoft to be used. 
More specifically, when there is an attempt to load a driver into the Windows kernel, DSE checks for a signature. If the driver isn't signed, it will not be loaded.

DSE is indeed a potent security feature, and for a long time, it has helped mitigate malicious kernel space code execution. However, over time, 
researchers have found ways to bypass DSE and load unsigned drivers. Today, it has become relatively easy to do so. 
This poses a significant security problem, as we explained before an attacker with kernel code execution is essentially game over.


Vulnerable drivers compromising the kernel
---
Currently, the most prevalent method of circumventing Driver Signature Enforcement (DSE) involves loading an existing driver 
that has a write vulnerability and then, various tactics are employed to disrupt the DSE verification process by manipulating memory at runtime.

This approach is widely recognized within cybersecurity communities and has been for some time. 
There are readily available online examples of working code that demonstrate the ease with which this tactic can be executed.

In an attempt to prevent this, Microsoft has incorporated a new mechanism into Windows aimed at detecting and blocking the loading of vulnerable drivers. 
However, their databases of vulnerable drivers appear to update very slowly, making it still remarkably simple to locate signed vulnerable drivers online that remain unblocked. 
Additionally, many of the vulnerable driver leader projects are versatile and dynamic, allowing for an effortless transition to another vulnerable driver with minimal modifications.

Another challenge arises from Microsoft's occasional limitation in blocking certain vulnerable drivers. 
In some cases, a driver may be widely used, and blocking it could result in the malfunction of numerous computers and servers, including ones performing critical tasks. 
Furthermore, some machines may face difficulties updating for various reasons.


Our hardening strategy with DLM
---
While Microsoft is working on mechanisms better than DSE to try and prevent malicious code execution and exploitation in kernel-space
these solutions are still early and can come with the cost of a lot of performance or create issues using other incompatible software.

In either case, we would like to make it harder for malware to perform kernel code execution. We can do that by running code every time
software attempts to load a driver. The code will check if that driver is inside an external database of vulnerable or malicious drivers or even inside
our database that could contain drivers that are just easy to find online or that have been recently shared on hacking forums.

This gives us that much more control over which drivers are being loaded and in theory it can allow us to block drivers by all sorts
of parameters. Not only for appearing in a DB but based on certain methods appearing in its import table or certain byte patterns being
found in the binary, the possibilities are endless and we might expand on the different types of analysis that are possible here in a future post.

When inspecting driver loaders in most cases we find that they call NtLoadDriver, meaning if we hook
that function we will be able to execute our code which will decide whether we want to forward the call to the actual NtLoadDriver function.


Selecting a hooking strategy
---
I've decided to use an inline hook over an IAT hook because, unlike IAT hooking, inline hooking
involves modifying the code at the instruction level rather than altering data structures. This can make it more challenging for anti-hooking techniques to identify and remove the hook.

Also, inline hooking provides better stability and compatibility since in some cases optimized or obfuscated code may not work well with IAT hooks due to the reliance on fixed addresses 
in the import table. Inline hooking, being more flexible, and operating directly at the instruction level can be more compatible with such scenarios.


Hooking NtLoadDriver
---
NtLoadDriver like most native API functions has no official documentation by Microsoft, but there is plenty of information about it online in 
lots of unofficial documentation websites and forums like undocumented.ntinternals.net, geoffchappell.com, and unknowncheats.me
just to name a few.

I will not be showing screenshots of every function that is being called in the code, as some of them are easy to understand by name and their internals are less relevant
to the point that is being explained, however, feel free to check out all of the code in the GitHub repository.

This is the function definition of NtLoadDrvier together with definitions of NTSTATUS STATUS_ACCESS_DENIED which we will return when the driver is found to be vulnerable or malicious and a max path size value which we will use later on.

![definitions](https://github.com/Nort721/Nort721.github.io/assets/24839815/dd4e0fb3-7722-4bfa-a4f7-4674afef16ff)

Next, we declare the following two fields to store the original first 5 bytes of the function which we are going to replace with the trampoline bytes and declare the address of NtLoadLibrary.

![declarations](https://github.com/Nort721/Nort721.github.io/assets/24839815/e19a6a0a-cf24-453b-a4b0-5f8a19de211c)

The hook is going to be inside a DLL that will be loaded to every process we want to monitor which in our case is all processes. The hook will be first installed when the DLL is attached to
a process.

![ScDllMainFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/3405377f-6ae5-4830-804b-dce4eafbc4e4)

The InstallInitHook function like it's called installs the hook for the first time and initializes the rest of the hooking logic. The parameters it takes are the address of NtLoadDriver which will be used to know
where to write the trampoline bytes and the address of the function our trampoline bytes will jump to which is named HookNtLoadDriver.

![ScInstallInitHookFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/d0fdf40a-f798-4215-bdfe-bc274caa4668)

InstallInlineHook is the function responsible for actually writing the hook or rather the trampoline to the first five bytes of the function, built out of 6 stages.
saving the original first five bytes, generating the trampoline bytes, changing memory permissions to allow for writing the hook bytes, writing the trampoline, changing memory permissions back to what they were,
clearing the instruction cash.

In a technical sense you don't have to set the memory permissions to what were but generally leaving messed up permissions behind is messy and if you are an attacker this leaves behind evidence, this doesn't
need to bother us in that sense because we are defending but this does hurt our stealthiness and can help indicate that this area contains a hook, so in either case, its good practice to stay clean.

As you can see, we are writing from the address of the function forward at the size of the trampoline.

![ScInstallInlineHookFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/c1cc0890-9cee-4aef-b1b8-35a6a9e78ed2)

![ScChangeMemPermFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/45a88b3d-3057-40a0-96a8-8ab0e32db7aa)

SaveBytes saves the bytes that are going to be overwritten by the bytes of the hook.

![ScSaveBytesFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/a3a00140-8b34-49f7-bff2-67e7db7c0f1d)

CreateInlineHookBytes creates an array containing the stub and copies the address to replace it with the placeholder 0xCC.

![ScCreateInlineHookBytesFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/dda769cc-4268-4594-93fb-86ff90588493)

HookNtLoadDriver is the function that we are jumping to every time NtLoadDriver is called. The parameter passed to NtLoadDriver is a pointer to a Unicode string that contains
the registry pathname of the service of the driver which we can use to find the driver's binary so we can inspect it. 

Our hooked function operates in a few stages, first get the file system path for the binary of the driver, use the file to verify that the driver
is safe, if it is, remove the trampoline bytes so we can call NtLoadDriver and then write the trampoline bytes back so we don't miss future calls. 
if the driver is found to be not safe we simply return NTSTATUS - STATUS_ACCESS_DENIED.

![ScHookNtLoadDriverFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/eed140a3-7941-438b-afcd-050f25f74bed)

VerifyDriverBinary takes the driver file path as a parameter and calls ReadBinary to read it from the disk. Then it calculates the driver's hash and sends it to the server, the
server checks if the hash exists in a db, if it does it replies with "rejected" otherwise it replies with "approved".

As I lightly touched on earlier this is where we can get creative and optionally add more mechanisms to try and determine whether the driver is vulnerable, whether it would be checking
with more existing databases, using more advanced signatures, you could decide to ban the usage of certain functions that are known to be vulnerable (a usermode example for usage of unsafe functions is strcpy) or that are very commonly misused in
ways that create write vulnerabilities, the possibilities are endless and are all enabled by this monitoring mechanism.

![ScVerifyDriverBinaryFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/6129cc72-8753-4a54-bc3f-2785ef79f9f2)

The CalcMemHash function is used to calculate the djb2 hash of the memory buffer that the driver has been read to by the ReadBinary function.

![ScCalcMemHashFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/1a2bd77a-6635-4e32-9b0f-e4fed275af9a)


Making the server
---
Our hook sends a request to a socket server rather than directly to a database mainly for security and to remove complexity from the hooking logic itself. we also do that because any future analysis really should be handled by a server using the server's resources
rather than on the client side. 

I decided to use Go to write the server for its relatively high runtime performance while also being easy and quick to use and mainly for its incredible concurrency model.
The server code is pretty short and simple, listening to incoming sockets and handling each connection in a separate goroutine concurrently. The list of vulnerable driver hashes is kept in a text file that represents the database,
this would of course be replaced with a proper database if used in a production environment, but for now, this is not necessary for the POC.

![ScServer](https://github.com/Nort721/Nort721.github.io/assets/24839815/1a2e34bf-caa4-4563-bb21-c2c497210204)


Hooking all processes in Windows (improve this section)
---
Now that we have the hook ready to go as a DLL file, we need to figure out how we want to inject it into all the user-mode processes in our target machine.
There are not many ways to go about this, but it seems like a pretty straightforward way is to use AppInitDLLs.
This registry value exists in the following path:
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows

This also requires enabling the LoadAppInit_DLLs value that's in the same path and setting RequireSignedAppInit_DLLs to 0 since our DLL is not signed.


Making the installer
---
I made a .net installer application with a GUI to automate
the process of setting up the system and make it easier to use.

![ScDLMInstaller](https://github.com/Nort721/Nort721.github.io/assets/24839815/9b93f7f2-11ac-49cb-a460-6c5a154d18a6)

When the installation button is pressed the following function executes.
The function copies hook.dll to a new folder called DLM inside the AppData folder, then it adds the path of that copied DLL to AppInitDLLs.

![ScInstallBtnFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/23018c87-ae9b-4cf2-b833-1d2861402791)
![ScAddDllAppInitFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/228df712-3dba-4985-8a4a-6b910e543e17)

As explained earlier we also need to set the LoadAppInit_DLLs value to 1 to enable AppInitDLL's functionality and we need to allow unsigned DLLs to be used
in AppInitDLLs by setting RequireSignedAppInit_DLLs to 0 since our DLL isn't signed.

![ScOtherValuesFuncs](https://github.com/Nort721/Nort721.github.io/assets/24839815/872fbf77-bf88-4da7-a5c1-f95a4061e46a)


And finally.. Run it!
---
First testing using an unsigned driver loader that utilizes a driver that has a write primitive vulnerability, this is a test with DLM installed.
And as we can see our hook intercepted the call and prevented the loading of the vulnerable driver.

![ScMonitoredTest](https://github.com/Nort721/Nort721.github.io/assets/24839815/67ad5c38-26f8-4681-93a4-c2db6f0739d9)

And testing with DLM uninstalled, the vulnerable driver is loaded and is used to load the unsigned driver with no issue.

![ScNotMonitoredTest](https://github.com/Nort721/Nort721.github.io/assets/24839815/081ffbad-1eca-4f7f-86e8-b907f6431ae2)


Conclusion
---
Additional hardening is desirable, especially in sensitive environments, blocking threats as early as possible is the name of the game and can help prevent the next malware attack.

This POC shows the concept well, however looking forward I found that multiple mechanisms that can be improved by utilizing the kernel's power ourselves which is what I've started working
on recently in combination with showcasing more analysis mechanisms to be implemented to the server.

As of now, I'm finalizing and cleaning the source code of this project and it will be posted shortly on my GitHub. Feel free to explore and provide feedback.
