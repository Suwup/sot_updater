#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>

char *process = "SoTGame.exe";
HANDLE handle;

typedef unsigned long long u64;
typedef unsigned long      u32;
typedef unsigned short     u16;
typedef unsigned char      u8;
typedef signed long long   s64;
typedef int                s32;
typedef signed short       s16;
typedef signed char        s8;

inline
bool sig_is_equal(u8 *data, u8 *sig, u64 size) {
    for (u64 i = 0; i < size; i++) {
        if (sig[i] && sig[i] != data[i]) return false;
    }
    return true;
}

inline
u8 *find_sig_start(u8 *start, u8 *end, u8 *sig, const size_t size) {
    for (auto it = start; it < end - size; it++) {
        if (sig_is_equal(it, sig, size)) return it;
    }
    return NULL;
}

u64 find_abs_addr_of_sig_in_module(u8 *base, u8 *end, u8 *sig, u64 size) {
    auto start = find_sig_start(base, end, sig, size);
    if (!start) return NULL;

    //
    // For example, names signature goes like: 48 8b 3d 00 00 00 00 48 ...
    //                                         ^^       ^^
    // Here we see that there are 3 instruction bytes and after that a 4-byte / 32-bit pointer to the rip-relative address.
    //
    // Now we get the amount of instruction bytes by incrementing t (the amount of instruction bytes)
    // until we get to a zero byte (our wildcard value if you would say so, like '??' is in ida signatures).
    //

    u32 t = 0;
    while (sig[t]) t++;

    // We get the relative-rip address by going past all instruction bytes, which is
    // at the pointer to the relative address, so we just need to dereference the pointer to get it.
    u32 *rel_addr_ptr = (u32 *)(start + t);

    // The rip (instruction pointer register) is the next instruction to execute
    // which means that is should be right after our instruction, in this case,
    // the 32-bit pointer to the rip-relative address.
    u64 rip = (u64)rel_addr_ptr + sizeof(*rel_addr_ptr);

    // We however want the absolute 8-byte / 64-bit pointer
    // which will be located at rip + the rip-relative address.
    return rip + *rel_addr_ptr;
}

inline
void write_string(char *string) {
    static auto out_handle = GetStdHandle(STD_OUTPUT_HANDLE);
        
    u32 written = 0;
    WriteFile(out_handle, string, (u32)strlen(string), &written, NULL);
}

inline
void write_pointer(u64 value) {
    char tmp[32];
    char *c = tmp;

    u8 base = 16;
    char hex_chars[] = "0123456789abcdef";
    char *start = c;
    do {
        u32 index = value % base;
        *c++ = hex_chars[index];
        value /= base;
    } while (value != 0);

    // Swap order since we write backwards.
    char *end = c;
    while (start < end) {
        char temp = *--end;
        *end = *start;
        *start++ = temp;
    }
    
    *c = 0;
    write_string(tmp);
}

inline
bool strings_are_equal(char *a, char *b) {
    if (!a) {
        if (!b) {
            return true;
        } else {
            return false;
        }
    }
    while (*a) {
        if (*a != *b) {
            return false;
        }
        a++;
        b++;
    }
    return !*b;
}

inline
char *string_is_within(char *a, char *b) {
    char *cp = a;
    char *s1, *s2;

    if (!*b) return a;
    while (*cp) {
        s1 = cp;
        s2 = b;

        while (*s2 && !(*s1-*s2)) s1++, s2++;
        if (!*s2) return(cp);
        cp++;
    }
    return NULL;
}

inline
int get_process_id(char *name) {
    void *snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    // Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
    // If you do not initialize dwSize, Process32First fails.
    PROCESSENTRY32 process_entry = { sizeof(PROCESSENTRY32) };
    
    while (Process32Next(snapshot, &process_entry)) {
        if (strings_are_equal(process_entry.szExeFile, name)) {
            CloseHandle(snapshot);
            return process_entry.th32ProcessID;
        }
    }

    CloseHandle(snapshot);
    return -1;
}

inline
u8 *get_virt_func_at_index(u8 *obj, u32 index) {
    u8 *vftable;
    ReadProcessMemory(handle, obj, &vftable, 8, NULL);

    u8 *func;
    ReadProcessMemory(handle, vftable + index * 8, &func, 8, NULL);
    return func;
}

inline
u8 *get_name_entry_at_index(u8 *global_names, u32 index) { // Pasted from ida, no idea what names should be, but it does not matter.
    u8 *chunks;
    ReadProcessMemory(handle, global_names, &chunks, 8, NULL);
    
    u8 *chunk;
    ReadProcessMemory(handle, chunks + 8 * (index / 0x4000), &chunk, 8, NULL);

    u8 *entry;
    ReadProcessMemory(handle, chunk + 8 * (index % 0x4000), &entry, 8, NULL);
    return entry;
}

inline
void read_name_entry(u8 *entry, char *buffer, u64 size) {
    ReadProcessMemory(handle, entry + 0x10, buffer, size, NULL);
}

inline
u32 get_object_name_index(u8 *object) {
    u32 index;
    ReadProcessMemory(handle, object + 0x18, &index, 4, NULL);
    return index;
}

inline
u8 *get_object_at_index(u8 *obj_objects, u32 index) {
    u8 *item;
    ReadProcessMemory(handle, obj_objects, &item, 8, NULL);

    u8 *object;
    ReadProcessMemory(handle, item + index * 24, &object, 8, NULL); // We need to multiply with the size of the object item https://prnt.sc/ylo6Sh6qAPcq.
    return object;
}

inline
void read_object_name(u8 *global_names, u8 *object, char *buffer, u64 size) {
    u32 name_index = get_object_name_index(object);
    u8 *entry = get_name_entry_at_index(global_names, name_index);
    read_name_entry(entry, buffer, size);
}

u8 *find_object(u8 *obj_objects, u8 *global_names, char *class_name, char *outer_name, char *object_name) {
    u32 num_elements;
    ReadProcessMemory(handle, obj_objects + 0xC, &num_elements, 4, NULL);
    
    for (u32 i = 0; i < num_elements; i++) {
        u8 *object = get_object_at_index(obj_objects, i);
        if (object) {
            u8 *object_class;
            ReadProcessMemory(handle, object + 0x10, &object_class, 8, NULL);

            u8 *outer;
            ReadProcessMemory(handle, object + 0x20, &outer, 8, NULL);
            
            if (object_class && outer) {
                char found_class_name[1024];
                char found_outer_name[1024];
                char found_object_name[1024];
                
                read_object_name(global_names, object_class, found_class_name, 1024);
                read_object_name(global_names, outer, found_outer_name, 1024);
                read_object_name(global_names, object, found_object_name, 1024);
                
                if (strings_are_equal(class_name, found_class_name) &&
                    string_is_within(found_outer_name, outer_name) &&
                    strings_are_equal(object_name, found_object_name)) {
                    return object;
                }
            }
        }
    }
    return NULL;
}

u64 find_offset_from_sig(u8 *base, u64 size, u8 *sig, u64 sig_size) {
    u8 chunk[0x1000];
    u64 chunk_size = sizeof(chunk);
    u64 read_total = 0;

    while (size > read_total) {
        ReadProcessMemory(handle, base + read_total, chunk, chunk_size, NULL);
        u64 s = find_abs_addr_of_sig_in_module(chunk, chunk + chunk_size - 1, sig, sig_size);
        if (s) {
            return (u8 *)s - chunk + read_total;
        }

        read_total += chunk_size;
    }

    return NULL;
}

void dump_offsets(u8 *base, u64 size) {
    u8 objects_sig[] = { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x54, 0xC8, 0x08 };
    u8 names_sig[] = { 0x48, 0x8b, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xff, 0x75, 0x3c };

    u64 obj_objects = find_offset_from_sig(base, size, objects_sig, sizeof(objects_sig));
    u64 global_names = find_offset_from_sig(base, size, names_sig, sizeof(names_sig));

    u8 *viewport = find_object(base + obj_objects, base + global_names, "AthenaGameViewportClient", "AthenaGameEngine", "AthenaGameViewportClient");
    u8 *ship_size = find_object(base + obj_objects, base + global_names, "Class", "Athena", "ShipSize");
    
    u64 process_event = get_virt_func_at_index(viewport, 0x37) - base;
    u64 post_render = get_virt_func_at_index(viewport, 0x56) - base;
    u64 create_default_object = get_virt_func_at_index(ship_size, 0x56) - base;

    write_string("obj objects offset: 0x");
    write_pointer(obj_objects);
    write_string("\n");

    write_string("global names offset: 0x");
    write_pointer(global_names);
    write_string("\n");
    
    write_string("process event offset: 0x");
    write_pointer(process_event);
    write_string("\n");

    write_string("post render offset: 0x");
    write_pointer(post_render);
    write_string("\n");

    write_string("create default object offset: 0x");
    write_pointer(create_default_object);
    write_string("\n");
}

int mainCRTStartup() {
    write_string("preparing dump for process \"");
    write_string(process);
    write_string("\"\n");

    int pid = get_process_id(process);
    if (pid == -1) return 0;

    write_string("found process\n");

    handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (!handle) return 0;

    write_string("got process handle\n");

    PROCESS_BASIC_INFORMATION info;
    NtQueryInformationProcess(handle, ProcessBasicInformation, &info, sizeof(info), 0);

    u8 *base;
    u8 *peb_base = (u8 *)info.PebBaseAddress;
    ReadProcessMemory(handle, peb_base + 0x10, &base, sizeof(base), NULL);
    write_string("got process base\n");

    u8 header_pe[0x1000];
    ReadProcessMemory(handle, base, header_pe, sizeof(header_pe), NULL);
    write_string("got pe header\n");

    auto header_dos = (IMAGE_DOS_HEADER *)header_pe;
    auto header_nt = (IMAGE_NT_HEADERS *)(header_pe + header_dos->e_lfanew);
    
    write_string("dumping offsets\n");
    dump_offsets(base, header_nt->OptionalHeader.SizeOfImage);
    
    CloseHandle(handle);
    write_string("closed handle\n");
    write_string("done\n");
    return 0;
}
