#ifndef HOOKTEMPLATE_H
#define HOOKTEMPLATE_H
#include<Windows.h>

// patch bytes function
class HooknPatch
{
public:
	//	Use of Patch or writememory Function: Create class HooknPatch hP ;
	//use hP.patchByte<LENGTH>(dst,src,LENGTH)
	//hP.patchByte<7>((BYTE*)d3d9Device[42], EndSceneBytes);

	//template non-type parameters used for template functions
	template<int LENGTH>
	void patchByte( BYTE* dst, BYTE* src )
	{
		DWORD oProc;
		VirtualProtect( dst, LENGTH, PAGE_EXECUTE_READWRITE, &oProc );
		RtlMoveMemory( dst, src, LENGTH );
		VirtualProtect( dst, LENGTH, oProc, &oProc );
	}

	// mid-function Detour and Hook
	// usage: hP.midDetour<LENGTH>(src,dst)
	template<int LENGTH>
	bool midDetour( char* src, char* dst )
	{
		if (LENGTH < 5)
			return false;
		DWORD oProc;
		VirtualProtect( src, LENGTH, PAGE_EXECUTE_READWRITE, &oProc );
		RtlFillMemory( src, LENGTH, 0x90 );
		uintptr_t relAddy = (uintptr_t) (dst - src - 5);
		*src = (char) 0xE9;
		*(uintptr_t*) (src + 1) = (uintptr_t) relAddy;
		VirtualProtect( src, LENGTH, oProc, &oProc );
		return true;
	}

	// trampoline hook function for saving register state
	// usage:hP.trampHook<LENGTH>(src,dst)
	//(tEndScene)(hP.trampHook<7>((char*)d3d9Device[42], (char*)hkEndScene));

	template <int LENGTH>
	char* trampHook( char* src, char* dst )
	{
		if (LENGTH < 5)
			return nullptr;
		char* gateway = (char*) VirtualAlloc( 0, LENGTH + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
		RtlMoveMemory( gateway, src, LENGTH );
		uintptr_t jumpAddress = (uintptr_t) (src - gateway - 5);
		*(gateway + LENGTH) = (char) 0xE9;
		*(uintptr_t*) (gateway + LENGTH + 1) = jumpAddress;
		if (midDetour<7>( src, dst )) // midDeotour another templated member function called here
		{
			return gateway;
		}
		else return nullptr;
	}

};


#endif