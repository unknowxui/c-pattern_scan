#include <Windows.h>
#include <stdio.h>

typedef struct PatternFunctionReturnValues {
    size_t size;
    int   data[256];
}PATTERNFNVALUES;

PATTERNFNVALUES pattern_to_byte( const char* pattern ) {
    PATTERNFNVALUES returnValue;
    returnValue.size = 0;
    memset( returnValue.data, 0, 256 );

    char* begin = ( char* )pattern;
    char* end = begin + strlen( pattern );

    for ( char* current = begin; current < end; current++ ) {
        if ( *current == '?' ) {
            current++;
            if ( *current == '?' ) {
                current++;
            }

            returnValue.data[returnValue.size] = -1;
            returnValue.size++;
        } else {
            returnValue.data[returnValue.size] = strtoul( current, &current, 16 );
            returnValue.size++;
        }
    }

    return returnValue;
}
void* pattern( const char* moduleName, const char* pattern ) {
    void* moduleBase = GetModuleHandleA( moduleName );
    if ( !moduleBase ) {
        return NULL;
    }

    PIMAGE_DOS_HEADER dosHeader  = ( PIMAGE_DOS_HEADER )moduleBase;
    PIMAGE_NT_HEADERS ntHeaders  = ( PIMAGE_NT_HEADERS )(( unsigned char* )moduleBase + dosHeader->e_lfanew);

    DWORD           sizeOfImage  = ntHeaders->OptionalHeader.SizeOfImage;
    PATTERNFNVALUES patternBytes = pattern_to_byte( pattern );
    unsigned char*  scanBytes    = (unsigned char*)(moduleBase);

    size_t s = patternBytes.size;
    int*   d = patternBytes.data;

    for ( auto i = 0ul; i < sizeOfImage - s; ++i ) {
        int found = 1;
        for ( auto j = 0ul; j < s; ++j ) {
            if ( scanBytes[i + j] != d[j] && d[j] != -1 ) {
                found = 0;
                break;
            }
        }
        if ( found ) {
            return &scanBytes[i];
        }
    }

    return NULL;
}

void main() {
    LoadLibrary( "kernel32.dll" );
    printf( "%p \n", pattern("kernel32.dll","4C 8B DC 48 83 EC 48 48 8B C2 48 F7 D8 4D 1B D2 49 83 63 ? ? 4D 23 D0 45 33 C0 4D 89 53 E8 49 89 53 E0 B2 01 49 89 4B D8 "));
}
