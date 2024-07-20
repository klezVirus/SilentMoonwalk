#include <Windows.h>

size_t GetCallstack(void* pReturnAddressArray[], size_t nReturnAddressArrayCapacity, const CONTEXT* pContext)
{
	CONTEXT           context;
	PRUNTIME_FUNCTION pRuntimeFunction;
	ULONG64           nImageBase = 0;
	ULONG64           nPrevImageBase = 0;
	size_t            nFrameIndex = 0;

	if (pContext)
	{
		RtlZeroMemory(&context, sizeof(context));
		context.Rip = pContext->Rip;
		context.Rsp = pContext->Rsp;
		context.Rbp = pContext->Rbp;
		context.ContextFlags = CONTEXT_CONTROL; // CONTEXT_CONTROL actually specifies SegSs, Rsp, SegCs, Rip, and EFlags. But for callstack tracing and unwinding, all that matters is Rip and Rsp.

		// In the case where we are calling 0, we might be able to unwind one frame and see if we are now in a valid stack frame for 
		// callstack generation. If not abort, otherwise we continue one frame past where the exception (calling 0) was performed
		if (context.Rip == 0 && context.Rsp != 0)
		{
			context.Rip = (ULONG64)(*(PULONG64)context.Rsp); // To consider: Use IsAddressReadable(pFrame) before dereferencing this pointer.
			context.Rsp += 8; // reset the stack pointer (+8 since we know there has been no prologue run requiring a larger number since RIP == 0)
		}

		if (context.Rip && (nFrameIndex < nReturnAddressArrayCapacity))
			pReturnAddressArray[nFrameIndex++] = (void*)(uintptr_t)context.Rip;
	}
	else // Else we are reading the current thread's callstack.
	{
		// To consider: Don't call the RtlCaptureContext function for EA_WINAPI_PARTITION_DESKTOP and 
		// instead use the simpler version below it which writes Rip/Rsp/Rbp. RtlCaptureContext is much 
		// slower. We need to verify that the 'quality' and extent of returned callstacks is good for 
		// the simpler version before using it exclusively.
		context.ContextFlags = CONTEXT_ALL; // Actually we should need only CONTEXT_INTEGER, so let's test that next chance we get.
		RtlCaptureContext(&context);
	}

	// The following loop intentionally skips the first call stack frame because 
	// that frame corresponds this function (GetCallstack).
	while (context.Rip && (nFrameIndex < nReturnAddressArrayCapacity))
	{
		// Try to look up unwind metadata for the current function.
		nPrevImageBase = nImageBase;
		__try
		{
			pRuntimeFunction = (PRUNTIME_FUNCTION)RtlLookupFunctionEntry(context.Rip, &nImageBase, NULL /*&unwindHistoryTable*/);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			// Something went wrong in RtlLookupFunctionEntry, and it is unknown
			// if it is recoverable; so just get out.
			return nFrameIndex;
		}

		if (pRuntimeFunction)
		{
			// RtlVirtualUnwind is not declared in the SDK headers for non-desktop apps, 
			// but for 64 bit targets it's always present and appears to be needed by the
			// existing RtlUnwindEx function. If in the end we can't use RtlVirtualUnwind
			// and Microsoft doesn't provide an alternative, we can implement RtlVirtualUnwind
			// ourselves manually (not trivial, but has the best results) or we can use
			// the old style stack frame following, which works only when stack frames are 
			// enabled in the build, which usually isn't so for optimized builds and for
			// third party code. 

			__try // Under at least the XBox One platform, RtlVirtualUnwind can crash here. It may possibly be due to the context being incomplete.
			{
				VOID* handlerData = NULL;
				ULONG64        establisherFramePointers[2] = { 0, 0 };
				RtlVirtualUnwind(UNW_FLAG_NHANDLER, nImageBase, context.Rip, pRuntimeFunction, &context, &handlerData, establisherFramePointers, NULL);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				context.Rip = NULL;
				context.ContextFlags = 0;
			}
		}
		else
		{
			// If we don't have a RUNTIME_FUNCTION, then we've encountered an error of some sort (mostly likely only for cases of corruption) or leaf function (which doesn't make sense, given that we are moving up in the call sequence). Adjust the stack appropriately.
			context.Rip = (ULONG64)(*(PULONG64)context.Rsp); // To consider: Use IsAddressReadable(pFrame) before dereferencing this pointer.
			context.Rsp += 8;
		}

		if (context.Rip)
		{
			if (nFrameIndex < nReturnAddressArrayCapacity)
				pReturnAddressArray[nFrameIndex++] = (void*)(uintptr_t)context.Rip;
		}
	}

	return nFrameIndex;
}