#include "unlock_file.h"
#include "unlock_file_diskio.h"
#include "ff.h"
#include "diskio.h"
#include <string.h>

#define UNLOCK_PATH "/unlock.txt"
#define UNLOCK_FILE_MAX_SIZE 256

static FATFS filesystem;

/* A normal memset can be optimized away; volatile keeps password wipes intact. */
static void clear_bytes(void *buffer, size_t size)
{
    volatile uint8_t *byte = buffer;

    while (size-- != 0)
        *byte++ = 0;
}

static void unmount_filesystem(void)
{
    f_mount(NULL, "", 0);
    clear_bytes(&filesystem, sizeof(filesystem));
}

static bool mount_filesystem(void)
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
    unmount_filesystem();
    clear_bytes(work, sizeof(work));
    return ready;
}

static bool read_password(const uint8_t *contents, size_t size,
                          uint8_t *password, size_t *password_len)
{
    const char prefix[] = "password:";
    const size_t prefix_len = sizeof(prefix) - 1;

    for (size_t offset = 0; offset + prefix_len < size; offset++) {
        if (memcmp(contents + offset, prefix, prefix_len) != 0)
            continue;

        size_t start = offset + prefix_len;
        size_t end = start;

        while (end < size && contents[end] != '\r' &&
               contents[end] != '\n' && contents[end] != '\0')
            end++;

        size_t length = end - start;
        if (length == 0 || length > UNLOCK_PASSWORD_MAX)
            return false;

        memcpy(password, contents + start, length);
        *password_len = length;
        return true;
    }

    return false;
}

bool unlock_file_read(uint8_t *password, size_t *password_len)
{
    FIL file;
    uint8_t contents[UNLOCK_FILE_MAX_SIZE];
    UINT bytes_read;
    bool found = false;

    clear_bytes(password, UNLOCK_PASSWORD_MAX);
    *password_len = 0;

    /* A fresh mount sees directory and FAT updates from the latest host writes. */
    if (!mount_filesystem())
        goto done;

    if (f_open(&file, UNLOCK_PATH, FA_READ) != FR_OK)
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

    found = read_password(contents, bytes_read, password, password_len);

close_file:
    if (f_close(&file) != FR_OK)
        found = false;

done:
    unmount_filesystem();
    clear_bytes(contents, sizeof(contents));
    if (!found) {
        clear_bytes(password, UNLOCK_PASSWORD_MAX);
        *password_len = 0;
    }
    return found;
}

bool unlock_file_delete(void)
{
    FIL file;
    uint8_t blank[UNLOCK_FILE_MAX_SIZE] = {0};
    UINT bytes_written;
    bool deleted = false;

    if (!mount_filesystem())
        goto done;

    if (f_open(&file, UNLOCK_PATH, FA_WRITE) != FR_OK)
        goto done;

    FSIZE_t size = f_size(&file);
    bool erased = size <= sizeof(blank) &&
                  f_write(&file, blank, (UINT)size, &bytes_written) == FR_OK &&
                  bytes_written == size;

    /* Close flushes the overwritten data before unlink frees its clusters. */
    if (f_close(&file) != FR_OK)
        erased = false;

    if (erased)
        deleted = f_unlink(UNLOCK_PATH) == FR_OK;

done:
    unmount_filesystem();
    return deleted;
}
