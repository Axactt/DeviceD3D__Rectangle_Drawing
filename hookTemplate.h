#ifndef HOOKTEMPLATE_H
#define HOOKTEMPLATE_H
#include<Windows.h>
#include<vector>
// patch bytes function
class HooknPatch
{
private:
	// This gatway variable stores the original bytes of function
	char* gateway;

public:
	
	//template non-type parameters used for template functions
	// mid-function Detour and Hook
	// usage: hP.midDetour<LENGTH>(lpOriginalFuncAddrs,lpFinalHookaddrs)
	template<int LENGTH>
	bool midDetour( char* lpOriginalFuncAddrs, char* lpFinalHookaddrs )
	{
		if (LENGTH < 5)
			return false;
		DWORD oProc;
		VirtualProtect( lpOriginalFuncAddrs, LENGTH, PAGE_EXECUTE_READWRITE, &oProc );
		RtlFillMemory( lpOriginalFuncAddrs, LENGTH, 0x90 );
		uintptr_t relAddy = (uintptr_t) (lpFinalHookaddrs - lpOriginalFuncAddrs - 5);
		*lpOriginalFuncAddrs = (char) 0xE9;
		*(uintptr_t*) (lpOriginalFuncAddrs + 1) = (uintptr_t) relAddy;
		VirtualProtect( lpOriginalFuncAddrs, LENGTH, oProc, &oProc );
		return true;
	}

	// trampoline hook function for saving register state
	// usage:hP.trampHook<LENGTH>(lpOriginalFuncAddrs,lpFinalHookaddrs)
	//(tEndScene)(hP.trampHook<7>((char*)d3d9Device[42], (char*)hkEndScene));

	template <int LENGTH>
	char* trampHook( char* lpOriginalFuncAddrs, char* lpFinalHookaddrs )
	{
		if (LENGTH < 5)
			return nullptr;

		// Do not redefine gateway here otherwise variable shadowing will occur 
		//Only assign so this way the variable gateway can be reused to patch back original bytes later
		 gateway = (char*) VirtualAlloc( 0, LENGTH + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
		
		 RtlMoveMemory( gateway, lpOriginalFuncAddrs, LENGTH );

		uintptr_t jumpAddress = (uintptr_t) (lpOriginalFuncAddrs - gateway - 5);
		*(gateway + LENGTH) = (char) 0xE9;
		*(uintptr_t*) (gateway + LENGTH + 1) = jumpAddress;
		if (midDetour<7>( lpOriginalFuncAddrs, lpFinalHookaddrs )) // midDeotour another templated member function called here
		{
			return gateway;
		}
		else return nullptr;
	}

	//	Use of Patch or writememory Function: To patch Back original Bytes for Unhook
	// Create class HooknPatch hP ;
	//use hP.patchByte<LENGTH>((char*)lpOriginalFuncAddrs)
	//hP.patchByte<7>((BYTE*)d3d9Device[42], );

	template<int LENGTH>
	void patchByte( char* lpOriginalFuncAddrs )
	{
		DWORD oProc;
		VirtualProtect( lpOriginalFuncAddrs, LENGTH, PAGE_EXECUTE_READWRITE, &oProc );
		RtlMoveMemory( lpOriginalFuncAddrs, gateway, LENGTH );
		VirtualProtect( lpOriginalFuncAddrs, LENGTH, oProc, &oProc );
	}

};


#endif