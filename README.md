# Phantom Bomber

Phantom Bomber is a remote process injector that first creates a shared section using phantom DLL hollowing/module overloading, then uses stack bombing to force Explorer (or another remote process with an alertable thread) to map and execute the shared section in a new thread.

Tested on Windows 10 version 2004, x64

![alt text](https://github.com/jasonb17/Phantom-Bomber/blob/main/demo.png?raw=true)

## Usage
```
    ____  __                __                     ____                  __             
   / __ \/ /_  ____ _____  / /_____  ____ ___     / __ )____  ____ ___  / /_  ___  _____
  / /_/ / __ \/ __ `/ __ \/ __/ __ \/ __ `__ \   / __  / __ \/ __ `__ \/ __ \/ _ \/ ___/
 / ____/ / / / /_/ / / / / /_/ /_/ / / / / / /  / /_/ / /_/ / / / / / / /_/ /  __/ /    
/_/   /_/ /_/\__,_/_/ /_/\__/\____/_/ /_/ /_/  /_____/\____/_/ /_/ /_/_.___/\___/_/    

Remote process injector combining Phantom DLL Hollowing and Stack Bombing.

REQUIRED

--payload-file <path> 

OPTIONAL

--alloc-type {dll-map-hollow|txf-dll-map-hollow||mapped} (default: mapped)
--exec-method {call|create-thread|create-thread-stealth} (default: call/same thread)
--target-tid <TID> (default: Explorer.exe alertable thread will be targeted)
--RWX-to-RX
--unmap-after-exec


--payload-file      The file containing the shellcode to be used as an implant.

--alloc-type        The way in which the dynamic memory used to hold the payload implant should be
                    created.
                    
                    dll-map-hollow      A view of an image section generated from a DLL in System32.
                    txf-dll-map-hollow  Phantom DLL Hollowing - A view of an image section generated
                                        from a transacted DLL from System32 which has already been implanted
                                        with the payload.
                    mapped              A mapped view of a section derived from the Windows Page File.

--exec-method       The method the stack bombed thread should use to execute the payload.
                    
                    call                Execute the payload in the same stack bombed thread with a RET
                                        gadget; Stack will be restored after payload completes execution.
                    create-thread       Execute the payload in a new thread with CreateThread. Original
                                        stack on bombed thread will be restored after new thread is created.
                    create-thread-stealth   Execute the payload in a new thread by first moving the 
                                            target payload address into RCX, then creating a new
                                            thread with an entrypoint of a "push RCX, ret" gadget. Does 
                                            not work vs CFG-enabled processes (like Explorer)
               
--target-tid        The thread ID to target. Must be alertable. If none is provided, a known alertable 
                    thread in Explorer that is safe for stack bombing will be targeted.

--RWX-to-RX         If passed, the mapped section with the payload will be VirtualProtected to RX (or 
                    the PE's original protections) after the payload is written. TXF-dll-map-hollow option 
                    automatically apply this.
                    If not passed, the mapped section will remain RWX. This is likely necessary if the payload
                    performs dynamic self-decryption upon execution (e.g. metasploit xor/dynamic)

--unmap-after-exec  If passed, the stack bombed thread will unmap the payload after execution.
```


## Explanation

A brief explanation of phantom DLL hollowing and stack bombing follows, after which this project itself is detailed.

#### Phantom DLL Hollowing

DLL Hollowing is a stealthy memory allocation + write technique that generally involves the following steps:
1. Create a shared, image-backed section from a legitimate DLL on disk (NtCreateSection with SEC_IMAGE flag)
2. Map the section into the local/a remote processes' memory (NtMapViewOfSection)
3. Change memory protection on some region (usually .text section) of the mapped section, which is large enough to accommodate the payload, to PAGE_READWRITE (VirtualProtect)
4. Write the payload to this region (memcpy)
5. Change the protection back to PAGE_EXECUTE_READ (VirtualProtect)

The payload can then be executed with an execution technique like CreateThread, or (more interestingly), stack bombing as explained below.

"Phantom" DLL hollowing is an extension of the technique that uses a transacted file handle to hide the modification of the image-backed section \[more detail to be added\]

See https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing for more details

#### Stack Bombing

See https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf technique #26 for more details

\[more detail to be added\]

#### Targeting Explorer

If no target thread ID is passed, the POC will target a known "alertable" thread in Explorer which consistently responds to queued APCs. Interestingly, this thread never calls one of the "alertable functions" referred to in the BlackHat presentation (SleepEx-> NtDelayExecution, WaitForSingleObjectEx-> NtWaitForSingleObject, WaitForMultipleObjectsEx-> NtWaitForMultipleObjects, SignalObjectAndWait-> NtSignalAndWaitForSingleObject, RealMsgWaitForMultipleObjectsEx-> NtUserMsgWaitForMultipleObjectsEx), nor takes any of the other paths to the alertable state mentioned in Ori Damari's APC series: https://repnz.github.io/posts/apc/user-apc/

Instead, its path to becoming alertable is calling NtQuerySystemInformation querying for SystemPolicyInformation, which leads to a lock via a KeWaitForMutexObject kernel call; this lock (as far as I can see) never releases under normal operation.

A future blog post on this injector will cover my deep dive into this thread.

## Detection/IOCs

(high level)
- ntqueueapcthread - unusual api call
- handle obtained to explorer - sysmon event id 10
- explorer obtains handle to section with unknown name
- phantom-dll-hollowing
    - from Forrest-Orr ([https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-ii-insights-from-moneta](https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-ii-insights-from-moneta))

        ![https://static.wixstatic.com/media/a27d24_fbb501ef46c34b899d90134654f66689~mv2.png/v1/fit/w_300,h_300,al_c,q_5/file.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/1d7de01b-2474-4ce4-90de-dc9d011ed9da/Untitled.png)

        _"Notably in the image above, the missing PEB module suspicion persists (since the region in question is technically image memory without a corresponding PEB module entry) but the image itself is unknown. This is because TxF isolates its transactions from other processes, including in this case Moneta. When attempting to query the name of the file associated with the image region from its underlying FILE_OBJECT using the PSAPI.DLL!GetMappedFileNameW API, external processes will fail in the unique instance that the section underlying the image mapping view was generated using a transacted handle created by an external process. This is the most robust method I’ve devised to reliably detect phantom DLL hollowing and process doppelganging. This also results in the subregions of this image mapping region (distinguished by their unique VAD entries in the kernel) being unable to be associated with PE sections as they are in Figure 2"_

- create-thread (without stealth option) - 0x00 suspicious thread entrypoint
- RWX-to-RX - calling virtualprotect from RW to RX

## Credit

Project inspired by and borrowing code from the following projects/blog posts/presentations. Much appreciation to the authors.

https://github.com/forrest-orr/phantom-dll-hollower-poc

https://api.github.com/repos/forrest-orr/artifacts-kit

https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing

https://github.com/SafeBreach-Labs/pinjectra

Blackhat 2019 - Windows Process Injection in 2019 Amit Klein, Itzik Kotler

https://github.com/BryanH-BAH/Ampulex
