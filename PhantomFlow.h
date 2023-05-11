#ifndef __PHANTOMFLOW_H__
#define __PHANTOMFLOW_H__

//
// PhantomFlow's task is to obscurify control flow and throw off conventional debug tracing
// whilst maintaining minimum performance overhead
//

#include <Windows.h>
#include <winternl.h>

namespace PhantomFlow
{
	/**
	 * @brief Applies PhantomFlow to an executable's entire .text section assuming this section contains only executable data
	 * 
	 * @param [in]     Path: The path to the executable on disk
	 * @param [in] SavePath: The path to save the modified executable to
	*/
	BOOL
	BuildExecutable( 
		IN LPCSTR Path,
		IN LPCSTR SavePath
		);
}

#endif