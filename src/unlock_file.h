#ifndef UNLOCK_FILE_H_
#define UNLOCK_FILE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UNLOCK_PASSWORD_MAX 128

/* Call once before exposing USB. Create FAT32 if the decoy does not have it. */
bool unlock_file_init(void);

/* Mount around find/delete while USB disk I/O is paused. */
bool unlock_file_mount(void);
void unlock_file_unmount(void);
const char *unlock_file_find(uint32_t lba, size_t password_offset, size_t *password_len);
bool unlock_file_delete(const char *path);

#endif /* UNLOCK_FILE_H_ */
