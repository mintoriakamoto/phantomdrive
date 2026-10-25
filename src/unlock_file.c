#include "unlock_file.h"
#include "unlock_file_diskio.h"
#include "ff.h"
#include "diskio.h"
#include <string.h>

#define UNLOCK_FILE_MAX_SIZE 256

static FATFS filesystem;

/* A normal memset can be optimized away; volatile keeps password wipes intact. */
static void clear_bytes(void *buffer, size_t size)
{
    volatile uint8_t *byte = buffer;

    while (size-- != 0)
        *byte++ = 0;
}

void unlock_file_unmount(void)
{
    f_mount(NULL, "", 0);
    clear_bytes(&filesystem, sizeof(filesystem));
}

bool unlock_file_mount(void)
{
    if (f_mount(&filesystem, "", 1) != FR_OK)
        return false;

    return filesystem.fs_type == FS_FAT32;
}

bool unlock_file_init(void)
{
    uint8_t work[FF_MAX_SS];
    FRESULT result = f_mount(&filesystem, "", 1);
    bool ready = false;

    if (result == FR_NO_FILESYSTEM ||
        (result == FR_OK && filesystem.fs_type != FS_FAT32)) {
        if (disk_status(0) & STA_NOINIT)
            goto done;

        const MKFS_PARM options = { .fmt = FM_FAT32 | FM_SFD, .n_fat = 2 };
        unlock_file_diskio_set_formatting(true);
        result = f_mkfs("", &options, work, sizeof(work));
        unlock_file_diskio_set_formatting(false);
        if (result != FR_OK)
            goto done;

        result = f_mount(&filesystem, "", 1);
    }

    ready = result == FR_OK && filesystem.fs_type == FS_FAT32;

done:
    unlock_file_unmount();
    clear_bytes(work, sizeof(work));
    return ready;
}

static bool matches_scrubbed_password(const uint8_t *contents, size_t size,
                                     size_t password_offset, size_t *password_len)
{
    const char prefix[] = "password:";
    const size_t prefix_len = sizeof(prefix) - 1;

    if (password_offset < prefix_len || password_offset >= size)
        return false;
    if (memcmp(contents + password_offset - prefix_len, prefix, prefix_len) != 0)
        return false;

    size_t length = *password_len;
    if (length > size - password_offset)
        length = size - password_offset;
    if (length == 0 || length > UNLOCK_PASSWORD_MAX)
        return false;

    for (size_t offset = 0; offset < length; offset++) {
        if (contents[password_offset + offset] != 0)
            return false;
    }

    size_t end = password_offset + length;
    if (end < size && contents[end] != '\r' && contents[end] != '\n' &&
        contents[end] != '\0')
        return false;

    *password_len = length;
    return true;
}

static bool file_contains_scrubbed_password(const char *path, uint32_t lba,
                                          size_t password_offset,
                                          size_t *password_len)
{
    FIL file;
    uint8_t contents[UNLOCK_FILE_MAX_SIZE];
    UINT bytes_read;
    size_t length = *password_len;
    bool found = false;

    if (f_open(&file, path, FA_READ) != FR_OK)
        goto done;

    FSIZE_t size = f_size(&file);
    if (size == 0)
        goto close_file;
    if (size > sizeof(contents))
        goto close_file;

    FRESULT result = f_read(&file, contents, (UINT)size, &bytes_read);
    if (result != FR_OK)
        goto close_file;
    if (bytes_read != size)
        goto close_file;

    if (file.sect == lba)
        found = matches_scrubbed_password(contents, bytes_read,
                                         password_offset, &length);

close_file:
    if (f_close(&file) != FR_OK)
        found = false;

done:
    clear_bytes(contents, sizeof(contents));
    if (found)
        *password_len = length;
    return found;
}

/* Find the file where password:xxxxxx was entered. When this is called password is already scrubbed*/
const char *unlock_file_find(uint32_t lba, size_t password_offset, size_t *password_len)
{
    static char path[FF_LFN_BUF + 2]; /* Root slash, UTF-8 filename and NUL. */
    DIR directory;
    FILINFO info;
    const char *found_path = NULL;

    if (f_opendir(&directory, "/") != FR_OK)
        return NULL;

    while (1) {
        FRESULT result = f_readdir(&directory, &info);
        if (result != FR_OK || info.fname[0] == '\0')
            break;
        if (info.fattrib & AM_DIR)
            continue;
        if (info.fsize == 0 || info.fsize > UNLOCK_FILE_MAX_SIZE)
            continue;

        path[0] = '/';
        strcpy(path + 1, info.fname);
        if (file_contains_scrubbed_password(path, lba, password_offset,
                                           password_len)) {
            found_path = path;
            break;
        }
    }

    if (f_closedir(&directory) != FR_OK)
        return NULL;
    return found_path;
}

bool unlock_file_delete(const char *path)
{
    FIL file;
    uint8_t blank[UNLOCK_FILE_MAX_SIZE] = {0};
    UINT bytes_written;

    unlock_file_diskio_reset_timeout();
    if (f_open(&file, path, FA_WRITE) != FR_OK)
        return false;

    FSIZE_t size = f_size(&file);
    if (size > sizeof(blank)) {
        f_close(&file);
        return false;
    }

    FRESULT write_result = f_write(&file, blank, (UINT)size, &bytes_written);
    /* Close flushes the overwritten data before unlink frees its clusters. */
    FRESULT close_result = f_close(&file);
    if (write_result != FR_OK)
        return false;
    if (bytes_written != size)
        return false;
    if (close_result != FR_OK)
        return false;

    return f_unlink(path) == FR_OK;
}
