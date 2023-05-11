#include "PhantomFlow.h"
#include "hde64.h"
#include <intrin.h>
#include <cstdio>

#ifndef ROUND_TO_ALIGNMENT
#define ROUND_TO_ALIGNMENT( x, n ) ( UINT_PTR )( ( UINT_PTR )( ( UINT_PTR )x + ( n - 1 ) ) & ~( UINT_PTR )( n - 1 ) )
#endif
#ifndef ALIGN_LOW
#define ALIGN_LOW( x, n ) ( UINT_PTR )( ( UINT_PTR )( x ) & ~( UINT_PTR )( n - 1 ) )
#endif 
#ifndef PAGE_SIZE
#define PAGE_SIZE ( UINT_PTR )( 0x1000 )
#endif
#ifndef NtCurrentProcess
#define NtCurrentProcess( ) ( HANDLE )( ( UINT_PTR )-1 )
#endif
#ifndef NtCurrentPeb
#define NtCurrentPeb( ) ( PPEB )( __readgsqword( 0x60 ) )
#endif

UINT8*                g_pfCurrentExecutableBuffer = NULL;
PIMAGE_NT_HEADERS     g_pfCurrentFileNtHeaders    = NULL;
PIMAGE_SECTION_HEADER g_pfCurrentFileSections     = NULL;
UINT64                g_pfCurrentFileSizeOnDisk   = NULL;

typedef BOOL( NTAPI* RtlAddVectoredExceptionHandler_t )( 
	IN UINT64 First, 
	IN PVOID Handler 
	);

typedef NTSTATUS( NTAPI* NtProtectVirtualMemory_t )( 
	IN     HANDLE  ProcessHandle,
	IN OUT PVOID   RegionToProtect,
	IN OUT PSIZE_T NumberOfBytes,
	IN     ULONG   Protect,
	OUT    PULONG  OldProtect
	);

#pragma pack( push, 1 )
typedef struct _PFINIT_SECTION_DATA
{
	//
	// Page containing our init shellcode and exception handler
	//
	UINT8 InitShellcode[ 0x800 ];
	UINT8 ExceptHandler[ 0x800 ];

	//
	// Copy of section header that pertains to the PfInit section
	//
	IMAGE_SECTION_HEADER SelfSectionHeader;

	//
	// Copy of the section header that pertains to the PageChk section
	//
	IMAGE_SECTION_HEADER PageChkSection;

	//
	//
	//
	IMAGE_SECTION_HEADER PhantomFlowSection;

	//
	// Copy of the section header that pertains to the protected section
	//
	IMAGE_SECTION_HEADER TextSection;

	//
	// The entry point that should be called 
	//
	UINT32 RealEntryPoint;

}PFINIT_SECTION_DATA, *PPFINIT_SECTION_DATA;

typedef struct _PAGECHK_DATA_ENTRY
{
	UINT32 Checksum;
	UINT32 CopyLength;
} PAGECHK_DATA_ENTRY, *PPAGECHK_DATA_ENTRY;

typedef struct _PAGECHK_DATA_TABLE
{
	//
	// The number of PageChk data entries in the list
	//
	UINT32              NumberOfEntries;

	//
	// The checksum of the list of entries
	//
	UINT64              ChecksumDataHash;

	//
	// The list of entries
	//
	PAGECHK_DATA_ENTRY Entries[ 1 ];
} PAGECHK_DATA_TABLE, *PPAGECHK_DATA_TABLE;
#pragma pack( pop )

UINT32
PfInstructionAlignedPageSize( 
	IN LPVOID AddressInPage
	)
{
	hde64s HDE64Data{ 
	};

	UINT8* CurrentPageBase = ( UINT8* )( ( UINT64 )AddressInPage & ~( 0xFFFull ) );
	UINT8* NextPageBase    = ( UINT8* )( ( UINT64 )AddressInPage |    0xFFFull ) + 1;
	UINT8* Data            = NextPageBase - 16;

	while ( Data < NextPageBase ) {
		Data += hde64_disasm( Data, &HDE64Data );
	}

	return ( UINT32 )( ( UINT64 )( Data - CurrentPageBase ) & 0xFFFFFFFF );
}

BOOL
PfPrepareExecutableForModification(
	IN LPCSTR FilePath
	)
{
	//
	// Open a handle to the target file
	//
	HANDLE FileHandle = CreateFileA( FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL );

	if ( FileHandle == INVALID_HANDLE_VALUE ) {
		return FALSE;
	}

	//
	// Obtain the size of the file
	//
	DWORD FileSizeHigh = NULL;
	DWORD FileSize     = GetFileSize( FileHandle, &FileSizeHigh );

	//
	// Assert failure for files greater than 4GB in size
	//
	if ( FileSizeHigh != NULL ) 
	{
		SetLastError( STATUS_NO_MEMORY );
		return FALSE;
	}

	//
	// Allocate a buffer for the file to be read from
	//
	UINT8* DiskFileBuffer = ( UINT8* )VirtualAlloc( NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

	if ( DiskFileBuffer == NULL ) {
		return FALSE;
	}

	//
	// Read the file into the buffer
	//
	if ( ReadFile( FileHandle, DiskFileBuffer, FileSize, NULL, NULL ) == NULL )
	{
		CloseHandle( FileHandle );
		VirtualFree( DiskFileBuffer, NULL, MEM_RELEASE );
		return FALSE;
	}

	//
	// Close our file handle
	//
	CloseHandle( FileHandle );

	//
	// Obtain the nt headers for the file to parse and map the file into it's virtual state
	//
	PIMAGE_NT_HEADERS ImageNtHeaders = ( PIMAGE_NT_HEADERS )( DiskFileBuffer + ( ( PIMAGE_DOS_HEADER )DiskFileBuffer )->e_lfanew );

	//
	// Allocate plenty of space for the file in it's virtual state to take into account section allocations
	//
	g_pfCurrentExecutableBuffer = ( UINT8* )VirtualAlloc( NULL, ImageNtHeaders->OptionalHeader.SizeOfImage * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

	if ( g_pfCurrentExecutableBuffer == NULL ) {
		VirtualFree( DiskFileBuffer, NULL, MEM_RELEASE );
		return FALSE;
	}

	//
	// Copy the headers from the file into the buffer
	//
	RtlCopyMemory( g_pfCurrentExecutableBuffer, DiskFileBuffer, ImageNtHeaders->OptionalHeader.SizeOfHeaders );

	g_pfCurrentFileSections = IMAGE_FIRST_SECTION( ImageNtHeaders );

	//
	// Map sections into their virtual locations
	//
	for ( UINT32 i = NULL; i < ImageNtHeaders->FileHeader.NumberOfSections; i++ )
	{
		RtlCopyMemory( 
			g_pfCurrentExecutableBuffer + g_pfCurrentFileSections[ i ].VirtualAddress, 
			DiskFileBuffer + g_pfCurrentFileSections[ i ].PointerToRawData, 
			g_pfCurrentFileSections[ i ].SizeOfRawData 
			);
	}

	g_pfCurrentFileNtHeaders = ( PIMAGE_NT_HEADERS )( g_pfCurrentExecutableBuffer + ( ( PIMAGE_DOS_HEADER )DiskFileBuffer )->e_lfanew );
	g_pfCurrentFileSections  = IMAGE_FIRST_SECTION( g_pfCurrentFileNtHeaders );

	//
	// Store the file size on disk for storage
	//
	g_pfCurrentFileSizeOnDisk = FileSize;

	//
	// Free our disk file buffer
	//
	VirtualFree( DiskFileBuffer, NULL, MEM_RELEASE );

	return TRUE;
}

PIMAGE_SECTION_HEADER
PfAppendSectionToImage( 
	IN LPCSTR SectionName, 
	IN UINT32 Characteristics,
	IN UINT32 Size
	)
{
	PIMAGE_SECTION_HEADER NewSection = &g_pfCurrentFileSections[ g_pfCurrentFileNtHeaders->FileHeader.NumberOfSections ];

	RtlCopyMemory( NewSection->Name, SectionName, min( lstrlenA( SectionName ), 8 ) );
	
	NewSection->Characteristics  = Characteristics;

	NewSection->PointerToRawData = ROUND_TO_ALIGNMENT( g_pfCurrentFileSizeOnDisk, g_pfCurrentFileNtHeaders->OptionalHeader.FileAlignment );
	NewSection->SizeOfRawData    = ROUND_TO_ALIGNMENT( Size, g_pfCurrentFileNtHeaders->OptionalHeader.FileAlignment );

	NewSection->VirtualAddress   = g_pfCurrentFileNtHeaders->OptionalHeader.SizeOfImage;
	NewSection->Misc.VirtualSize = ROUND_TO_ALIGNMENT( Size, g_pfCurrentFileNtHeaders->OptionalHeader.SectionAlignment );

	g_pfCurrentFileNtHeaders->OptionalHeader.SizeOfImage += NewSection->Misc.VirtualSize;
	g_pfCurrentFileSizeOnDisk                            += NewSection->SizeOfRawData + ROUND_TO_ALIGNMENT( 
		g_pfCurrentFileSizeOnDisk, g_pfCurrentFileNtHeaders->OptionalHeader.FileAlignment ) - g_pfCurrentFileSizeOnDisk;

	g_pfCurrentFileNtHeaders->FileHeader.NumberOfSections++;

	return NewSection;
}

PIMAGE_SECTION_HEADER
PfGetSectionByName( 
	IN LPCSTR SectionName 
	)
{
	UINT32 SectionNameLength = min( lstrlenA( SectionName ), 8 );

	for ( UINT32 i = NULL; i < g_pfCurrentFileNtHeaders->FileHeader.NumberOfSections; i++ )
	{
		if ( RtlCompareMemory( g_pfCurrentFileSections[ i ].Name, SectionName, SectionNameLength ) == SectionNameLength ) {
			return &g_pfCurrentFileSections[ i ];
		}
	}

	return NULL;
}

FORCEINLINE
UINT32
PfGeneratePageChecksum( 
	IN LPVOID Page 
	)
{
	UINT64* CRCIterator = ( UINT64* )( ( UINT64 )Page & ~( 0xFFFull ) );
	UINT32  CRC         = NULL;

	for ( UINT64 i = NULL; i < 512; i++ ) {
		CRC = _mm_crc32_u64( CRC, CRCIterator[ i ] );
	}

	return CRC;
}

BOOL
PfWriteExecutableToDisk(
	IN LPCSTR FilePath
	)
{
	BOOL                  Result         = NULL;

	//
	// Allocate a buffer to restore the file to it's previous disk state in
	//
	UINT8*                DiskFileBuffer = ( UINT8* )VirtualAlloc( NULL, g_pfCurrentFileSizeOnDisk, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

	//
	// Create a new file on disk to write the modified file to
	//
	HANDLE                FileHandle     = CreateFileA( FilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL );

	if ( FileHandle == INVALID_HANDLE_VALUE || DiskFileBuffer == NULL ) {
		goto RET_EARLY;
	}

	//
	// Copy the nt headers to the start of the file buffer
	//
	RtlCopyMemory( DiskFileBuffer, g_pfCurrentExecutableBuffer, g_pfCurrentFileNtHeaders->OptionalHeader.SizeOfHeaders );

	//
	// Map the sections back to their physical format
	//
	for ( UINT32 i = NULL; i < g_pfCurrentFileNtHeaders->FileHeader.NumberOfSections; i++ ) 
	{
		RtlCopyMemory( 
			DiskFileBuffer + g_pfCurrentFileSections[ i ].PointerToRawData, 
			g_pfCurrentExecutableBuffer + g_pfCurrentFileSections[ i ].VirtualAddress, 
			g_pfCurrentFileSections[ i ].SizeOfRawData 
			);
	}

	//
	// Write to our newly created file on disk
	//
	Result = WriteFile( FileHandle, DiskFileBuffer, g_pfCurrentFileSizeOnDisk, NULL, NULL );

RET_EARLY:

	//
	// Free everything and close the handle
	//
	VirtualFree( g_pfCurrentExecutableBuffer, NULL, MEM_RELEASE );
	VirtualFree( DiskFileBuffer, NULL, MEM_RELEASE );
	CloseHandle( FileHandle );
	
	return Result;
}

FORCEINLINE
VOID
PfPageChkEncrypt( 
	IN PPAGECHK_DATA_TABLE PageChkData,
	IN LPVOID              Address,
	IN UINT64              Len
	)
{
	UINT8*  Iterator = ( UINT8* )Address;
	while ( Iterator < ( UINT8* )Address + Len ) 
	{
		UINT64 PageRelativeNumber = ( UINT64 )Iterator & ( PAGE_SIZE - 1 );
		UINT8  XorByte            = ( PageChkData->ChecksumDataHash >> ( ( PageRelativeNumber % 8 ) * 8 ) );

		*Iterator ^= XorByte;
		*Iterator  = _rotl8( *Iterator, XorByte ^ PageRelativeNumber );

		Iterator++;
	}
}

FORCEINLINE
VOID
PfPageChkDecrypt( 
	IN PPAGECHK_DATA_TABLE PageChkData,
	IN LPVOID              Address,
	IN UINT64              Len
	)
{
	UINT8*  Iterator = ( UINT8* )Address;
	while ( Iterator < ( UINT8* )Address + Len )
	{
		UINT64 PageRelativeNumber = ( UINT64 )Iterator & ( PAGE_SIZE - 1 );
		UINT8  XorByte            = ( PageChkData->ChecksumDataHash >> ( ( PageRelativeNumber % 8 ) * 8 ) );

		*Iterator = _rotr8( *Iterator, XorByte ^ PageRelativeNumber );
		*Iterator ^= XorByte;

		Iterator++;
	}
}

FORCEINLINE
VOID
PfExceptionAddPage( 
	IN PPAGECHK_DATA_TABLE PageChk,
	IN UINT8*              ExecSectionBase,
	IN UINT8*              PfSectionBase,
	IN UINT8*              ExceptionAddress
	)
{
	UINT64 ExceptionPageNumber = ( ( ( UINT64 )ExceptionAddress - ( UINT64 )ExecSectionBase ) & ~( 0xFFFull ) ) >> 12;

	__movsb( 
		ExecSectionBase + ( ExceptionPageNumber * PAGE_SIZE ),
		PfSectionBase   + ( ExceptionPageNumber * 0x1000 ), 
		PageChk->Entries[ ExceptionPageNumber ].CopyLength 
		);

	PfPageChkDecrypt( PageChk, ( UINT8* )ExecSectionBase + ( ExceptionPageNumber * 0x1000 ), PageChk->Entries[ ExceptionPageNumber ].CopyLength );
}

#pragma optimize( "", off )
DECLSPEC_NOINLINE
LONG
NTAPI
PfInitShellcode(
	IN LPVOID Pointer,
	IN UINT32 Reason,
	IN LPVOID Reserved
	)
{
	//
	// Obtain the section data to resolve information 
	//
	PPFINIT_SECTION_DATA ModuleData = ( PPFINIT_SECTION_DATA )PfInitShellcode;

	//
	// Resolve the base address of the current module
	//
	UINT8* ModuleBase = ( UINT8* )PfInitShellcode - ModuleData->SelfSectionHeader.VirtualAddress;

	PPEB Peb = NtCurrentPeb( );

	if ( Peb == NULL ) {
		return NULL;
	}

	PLIST_ENTRY ListBase = &Peb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY CurEntry = ListBase->Flink;

	while ( CurEntry != ListBase )
	{
		PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD( CurEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );

		PUNICODE_STRING BaseDllName = ( PUNICODE_STRING )&LdrEntry->Reserved4;

		//
		// Resolve NTDLL to obtain RtlAddVectoredExceptionHandler
		//
		if ( *( UINT64* )BaseDllName->Buffer == 0x6C00640074006E )
		{
			UINT8* NtDllBase = ( UINT8* )LdrEntry->DllBase;

			PIMAGE_NT_HEADERS NtDllNtHeaders = ( PIMAGE_NT_HEADERS )( NtDllBase + ( ( PIMAGE_DOS_HEADER )LdrEntry->DllBase )->e_lfanew );

			PIMAGE_EXPORT_DIRECTORY ExportDirectory = ( PIMAGE_EXPORT_DIRECTORY )( NtDllBase +
				NtDllNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );

			UINT32* FunctionList = ( UINT32* )( NtDllBase + ExportDirectory->AddressOfFunctions );
			UINT32* NameList     = ( UINT32* )( NtDllBase + ExportDirectory->AddressOfNames );
			UINT16* NameOrdinals = ( UINT16* )( NtDllBase + ExportDirectory->AddressOfNameOrdinals );

			for ( UINT32 i = NULL; i < ExportDirectory->NumberOfFunctions; i++ )
			{
				CHAR* FunctionName = ( CHAR* )( NtDllBase + NameList[ i ] );

				if ( *( ( UINT64* )FunctionName + 0 ) == 0x65566464416C7452 &&
					 *( ( UINT64* )FunctionName + 1 ) == 0x78456465726F7463 )
				{
					RtlAddVectoredExceptionHandler_t f_RtlAddVectoredExceptionHandler = ( RtlAddVectoredExceptionHandler_t )( 
						NtDllBase + FunctionList[ NameOrdinals[ i ] ] );

					f_RtlAddVectoredExceptionHandler( TRUE, ModuleData->ExceptHandler );
				}

				if ( *( ( UINT64* )FunctionName + 0 ) == 0x6365746F7250744E )
				{
					NtProtectVirtualMemory_t f_NtProtectVirtualMemory = ( NtProtectVirtualMemory_t )( NtDllBase + FunctionList[ NameOrdinals[ i ] ] );

					LPVOID BaseToProtect = ModuleBase + ModuleData->TextSection.VirtualAddress;
					UINT64 SizeToProtect = ModuleData->TextSection.Misc.VirtualSize;
					ULONG  OldProtect    = NULL;

					f_NtProtectVirtualMemory( NtCurrentProcess( ), &BaseToProtect, &SizeToProtect, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &OldProtect );
				}
			}
		}

		CurEntry = CurEntry->Flink;
	}

	//
	// Call the real entry point
	//
	( ( LONG( WINAPI* )( LPVOID, UINT32, LPVOID ) )( ModuleBase + ModuleData->RealEntryPoint ) )(
		Pointer,
		Reason,
		Reserved
		);
}

DECLSPEC_NOINLINE
LONG
WINAPI
PfExceptionHandler( 
	IN LPEXCEPTION_POINTERS ExceptionPointers 
	)
{
	//
	// Obtain the start of the PfInit section to resolve the section data 
	//
	UINT8* PfInitSectionStart = ( UINT8* )( ( UINT8* )PfExceptionHandler - 0x800 );

	//
	// Obtain the module data 
	//
	PPFINIT_SECTION_DATA ModuleData = ( PPFINIT_SECTION_DATA )PfInitSectionStart;

	//
	// Resolve the base address of the current module
	//
	UINT8* ModuleBase = PfInitSectionStart - ModuleData->SelfSectionHeader.VirtualAddress;

	//
	// Obtain the nt headers of the current module
	//
	PIMAGE_NT_HEADERS ModuleNtHeaders = ( PIMAGE_NT_HEADERS )( ModuleBase + ( ( PIMAGE_DOS_HEADER )ModuleBase )->e_lfanew );

	PCONTEXT          ContextRecord   = ExceptionPointers->ContextRecord;
	PEXCEPTION_RECORD ExceptionRecord = ExceptionPointers->ExceptionRecord;

	//
	// Obtain the .text section size and base address
	//
	UINT8* TextSectionBase = ModuleBase + ModuleData->TextSection.VirtualAddress;
	UINT32 TextSectionSize = ModuleData->TextSection.Misc.VirtualSize;

	//
	// Obtain the list of entries in PageChk
	//
	PPAGECHK_DATA_TABLE PageCheck = ( PPAGECHK_DATA_TABLE )( ModuleBase + ModuleData->PageChkSection.VirtualAddress );

	//
	// Obtain the PhantomFlow data
	//
	UINT8* PhantomFlowSectionBase = ( UINT8* )ModuleBase + ModuleData->PhantomFlowSection.VirtualAddress;

	if ( ExceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION ||
		 ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION )
	{
		UINT64 ExceptionAddress = ContextRecord->Rip;

		if ( ExceptionRecord->ExceptionCode             == STATUS_GUARD_PAGE_VIOLATION &&
		   ( ExceptionRecord->ExceptionInformation[ 0 ] == NULL || ExceptionRecord->ExceptionInformation[ 0 ] == 1 ) ) 
		{
			ExceptionAddress = ExceptionRecord->ExceptionInformation[ 1 ];
		}

		if ( ( UINT8* )ExceptionAddress <= ( TextSectionBase ) || ( UINT8* )ExceptionAddress >= ( TextSectionBase + TextSectionSize ) )
		{
			//
			// If the exception did not occur within the .text section, forward it
			//
			return EXCEPTION_CONTINUE_SEARCH;
		}
		
		PfExceptionAddPage( PageCheck, TextSectionBase, PhantomFlowSectionBase, ( UINT8* )ExceptionAddress );

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}
#pragma optimize( "", on )

//
// CONTINUE TOMORROW WITH THE ENCRYPTION/DECRYPTION PART 
//

BOOL
PhantomFlow::BuildExecutable( 
	IN LPCSTR Path,
	IN LPCSTR SavePath
	)
{
	if ( PfPrepareExecutableForModification( Path ) == FALSE ) {
		return FALSE;
	}

	PIMAGE_SECTION_HEADER ExecutableSection = PfGetSectionByName( ".text" );
	UINT64                NumberOfExecPages = ( ( ( UINT64 )ExecutableSection->Misc.VirtualSize + 0xFFFull ) & ~( 0xFFFull ) ) >> 12ull;

	//
	// Make the .text section writable
	//
	ExecutableSection->Characteristics |= IMAGE_SCN_MEM_WRITE;

	//
	// Allocate an executable section for our entry point shellcode
	//
	PIMAGE_SECTION_HEADER PfInitSection = PfAppendSectionToImage( 
		"PFINIT", 
		ExecutableSection->Characteristics, 
		0x1000 * 2 
		);

	PPFINIT_SECTION_DATA PfInitData = ( PPFINIT_SECTION_DATA )( g_pfCurrentExecutableBuffer + PfInitSection->VirtualAddress );

	//
	// Store our handlers
	//
	RtlCopyMemory( PfInitData->InitShellcode, &PfInitShellcode,    0x800 );
	RtlCopyMemory( PfInitData->ExceptHandler, &PfExceptionHandler, 0x800 );

	//
	// Store the original entry point to be called by the shellcode
	//
	PfInitData->RealEntryPoint = g_pfCurrentFileNtHeaders->OptionalHeader.AddressOfEntryPoint;

	//
	// Make a copy of the .text section to store it's encrypted contents
	//
	PIMAGE_SECTION_HEADER PhantomFlowSection = PfAppendSectionToImage( 
		"PHNTFLOW",
		IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
		ExecutableSection->Misc.VirtualSize
		);

	//
	// Make a section to store the checksums that correspond to each executable page
	//
	PIMAGE_SECTION_HEADER PageChecksumSection = PfAppendSectionToImage(
		"PAGECHK",
		IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
		NumberOfExecPages * sizeof( PAGECHK_DATA_ENTRY )
		);

	//
	// Store a copy of these section headers for resolving purposes in the init shellcode
	//
	RtlCopyMemory( &PfInitData->SelfSectionHeader,  PfInitSection,       sizeof( IMAGE_SECTION_HEADER ) );
	RtlCopyMemory( &PfInitData->TextSection,        ExecutableSection,   sizeof( IMAGE_SECTION_HEADER ) );
	RtlCopyMemory( &PfInitData->PhantomFlowSection, PhantomFlowSection,  sizeof( IMAGE_SECTION_HEADER ) );
	RtlCopyMemory( &PfInitData->PageChkSection,     PageChecksumSection, sizeof( IMAGE_SECTION_HEADER ) );

	PPAGECHK_DATA_TABLE PageChkTable = ( PPAGECHK_DATA_TABLE )( g_pfCurrentExecutableBuffer + PageChecksumSection->VirtualAddress );

#define PAGECHK_HASH_OFFSET 0x127A01EE20921A81
#define PAGECHK_HASH_PRIME  0x2B0B47A1

	PageChkTable->NumberOfEntries  = NumberOfExecPages;
	PageChkTable->ChecksumDataHash = PAGECHK_HASH_OFFSET;

	for ( UINT64 i = NULL; i < PageChkTable->NumberOfEntries; i++ ) 
	{
		UINT8* CurPg = g_pfCurrentExecutableBuffer + ExecutableSection->VirtualAddress + ( i * 0x1000 );

		//
		// Store a crc32 checksum of each page along with an instruction safe copy length in the PageChk section
		//
		PageChkTable->Entries[ i ].Checksum   = PfGeneratePageChecksum      ( CurPg );
		PageChkTable->Entries[ i ].CopyLength = PfInstructionAlignedPageSize( CurPg );

		//
		// Create a hash of all page checksums
		//
		PageChkTable->ChecksumDataHash ^=  PageChkTable->Entries[ i ].Checksum;
		PageChkTable->ChecksumDataHash =  _rotl64( PageChkTable->ChecksumDataHash, 32 );
		PageChkTable->ChecksumDataHash *= PAGECHK_HASH_PRIME;
	}

	// 
	// Copy over the contents of the .text section into our new section
	//
	RtlCopyMemory( 
		g_pfCurrentExecutableBuffer + PhantomFlowSection->VirtualAddress, 
		g_pfCurrentExecutableBuffer + ExecutableSection->VirtualAddress, 
		ExecutableSection->Misc.VirtualSize 
		);

	PfPageChkEncrypt( PageChkTable, g_pfCurrentExecutableBuffer + PhantomFlowSection->VirtualAddress, PhantomFlowSection->Misc.VirtualSize );

	//
	// Redirect the entry point to our PfInit shellcode
	//
	g_pfCurrentFileNtHeaders->OptionalHeader.AddressOfEntryPoint = PfInitSection->VirtualAddress;

	for ( UINT64 i = NULL; i < ExecutableSection->Misc.VirtualSize; i++ ) 
	{
		UINT8* CurrentByte = ( UINT8* )( g_pfCurrentExecutableBuffer + ExecutableSection->VirtualAddress + i );

		*CurrentByte = 0xFB;
	}

	return PfWriteExecutableToDisk( SavePath );
}