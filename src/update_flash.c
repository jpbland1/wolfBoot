/* update_flash.c
 *
 * Implementation for Flash based updater
 *
 *
 * Copyright (C) 2021 wolfSSL Inc.
 *
 * This file is part of wolfBoot.
 *
 * wolfBoot is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfBoot is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <stdio.h>
#include <string.h>
#include "loader.h"
#include "image.h"
#include "hal.h"
#include "spi_flash.h"
#include "wolfboot/wolfboot.h"
#include "delta.h"


#ifdef RAM_CODE
extern unsigned int _start_text;
static volatile const uint32_t __attribute__((used)) wolfboot_version = WOLFBOOT_VERSION;

#ifdef EXT_FLASH
#  ifndef BUFFER_DECLARED
#  define BUFFER_DECLARED
static uint8_t buffer[FLASHBUFFER_SIZE];
#  endif
#endif

#ifdef EXT_ENCRYPTED
#include "encrypt.h"
#endif

static void RAMFUNCTION wolfBoot_erase_bootloader(void)
{
    uint32_t len = WOLFBOOT_PARTITION_BOOT_ADDRESS - ARCH_FLASH_OFFSET;
    hal_flash_erase(ARCH_FLASH_OFFSET, len);

}

#include <string.h>

static void RAMFUNCTION wolfBoot_self_update(struct wolfBoot_image *src)
{
    uint32_t pos = 0;
    uint32_t src_offset = IMAGE_HEADER_SIZE;

    hal_flash_unlock();
    wolfBoot_erase_bootloader();
#ifdef EXT_FLASH
    if (PART_IS_EXT(src)) {
        while (pos < src->fw_size) {
            uint8_t buffer[FLASHBUFFER_SIZE];
            if (src_offset + pos < (src->fw_size + IMAGE_HEADER_SIZE + FLASHBUFFER_SIZE))  {
                uint32_t opos = pos + ((uint32_t)&_start_text);
                ext_flash_check_read((uintptr_t)(src->hdr) + src_offset + pos, (void *)buffer, FLASHBUFFER_SIZE);
                hal_flash_write(opos, buffer, FLASHBUFFER_SIZE);
            }
            pos += FLASHBUFFER_SIZE;
        }
        goto lock_and_reset;
    }
#endif
    while (pos < src->fw_size) {
        if (src_offset + pos < (src->fw_size + IMAGE_HEADER_SIZE + FLASHBUFFER_SIZE))  {
            uint8_t *orig = (uint8_t*)(src->hdr + src_offset + pos);
            hal_flash_write(pos + (uint32_t)&_start_text, orig, FLASHBUFFER_SIZE);
        }
        pos += FLASHBUFFER_SIZE;
    }
#ifdef EXT_FLASH
lock_and_reset:
#endif
    hal_flash_lock();
    arch_reboot();
}

void wolfBoot_check_self_update(void)
{
    uint8_t st;
    struct wolfBoot_image update;

    /* Check for self update in the UPDATE partition */
    if ((wolfBoot_get_partition_state(PART_UPDATE, &st) == 0) && (st == IMG_STATE_UPDATING) &&
            (wolfBoot_open_image(&update, PART_UPDATE) == 0) &&
            wolfBoot_get_image_type(PART_UPDATE) == (HDR_IMG_TYPE_WOLFBOOT | HDR_IMG_TYPE_AUTH)) {
        uint32_t update_version = wolfBoot_update_firmware_version();
        if (update_version <= wolfboot_version) {
            hal_flash_unlock();
            wolfBoot_erase_partition(PART_UPDATE);
            hal_flash_lock();
            return;
        }
        if (wolfBoot_verify_integrity(&update) < 0)
            return;
        if (wolfBoot_verify_authenticity(&update) < 0)
            return;
        PART_SANITY_CHECK(&update);
        wolfBoot_self_update(&update);
    }
}
#endif /* RAM_CODE for self_update */

static int RAMFUNCTION wolfBoot_copy_sector(struct wolfBoot_image *src, struct wolfBoot_image *dst, uint32_t sector)
{
    uint32_t pos = 0;
    uint32_t src_sector_offset = (sector * WOLFBOOT_SECTOR_SIZE);
    uint32_t dst_sector_offset = (sector * WOLFBOOT_SECTOR_SIZE);
#ifdef EXT_ENCRYPTED
    uint8_t key[ENCRYPT_KEY_SIZE];
    uint8_t nonce[ENCRYPT_NONCE_SIZE];
    uint32_t iv_counter;
#endif

    if (src == dst)
        return 0;

    if (src->part == PART_SWAP)
        src_sector_offset = 0;
    if (dst->part == PART_SWAP)
        dst_sector_offset = 0;

#ifdef EXT_ENCRYPTED
    wolfBoot_get_encrypt_key(key, nonce);
    if(src->part == PART_SWAP)
        iv_counter = dst_sector_offset;
    else
        iv_counter = src_sector_offset;

    iv_counter /= ENCRYPT_BLOCK_SIZE;
    crypto_set_iv(nonce, iv_counter);
#endif

#ifdef EXT_FLASH
    if (PART_IS_EXT(src)) {
#ifndef BUFFER_DECLARED
#define BUFFER_DECLARED
        static uint8_t buffer[FLASHBUFFER_SIZE];
#endif
        wb_flash_erase(dst, dst_sector_offset, WOLFBOOT_SECTOR_SIZE);
        while (pos < WOLFBOOT_SECTOR_SIZE)  {
          if (src_sector_offset + pos <
              (src->fw_size + IMAGE_HEADER_SIZE + FLASHBUFFER_SIZE)) {
              /* bypass decryption, copy encrypted data into swap */
              if (dst->part == PART_SWAP) {
                  ext_flash_read((uintptr_t)(src->hdr) + src_sector_offset + pos,
                                 (void *)buffer, FLASHBUFFER_SIZE);
              } else {
                  ext_flash_check_read((uintptr_t)(src->hdr) + src_sector_offset +
                                         pos,
                                     (void *)buffer, FLASHBUFFER_SIZE);
              }

              wb_flash_write(dst,
                             dst_sector_offset + pos, buffer, FLASHBUFFER_SIZE);
            }
            pos += FLASHBUFFER_SIZE;
        }
        return pos;
    }
#endif
    wb_flash_erase(dst, dst_sector_offset, WOLFBOOT_SECTOR_SIZE);
    while (pos < WOLFBOOT_SECTOR_SIZE) {
        if (src_sector_offset + pos < (src->fw_size + IMAGE_HEADER_SIZE + FLASHBUFFER_SIZE))  {
            uint8_t *orig = (uint8_t*)(src->hdr + src_sector_offset + pos);
            wb_flash_write(dst, dst_sector_offset + pos, orig, FLASHBUFFER_SIZE);
        }
        pos += FLASHBUFFER_SIZE;
    }
    return pos;
}

#ifdef DELTA_UPDATES

    #ifndef DELTA_BLOCK_SIZE
    #   define DELTA_BLOCK_SIZE 1024
    #endif

static int wolfBoot_delta_update(struct wolfBoot_image *boot,
    struct wolfBoot_image *update, struct wolfBoot_image *swap, int inverse,
    int resume_inverse)
{
    int sector = 0;
    int ret;
    uint8_t flag, st;
    int hdr_size;
    uint8_t delta_blk[DELTA_BLOCK_SIZE];
    uint32_t offset = 0;
    uint16_t ptr_len;
    uint32_t *img_offset;
    uint16_t *img_size;
    uint32_t total_size;
    WB_PATCH_CTX ctx;
#ifdef EXT_ENCRYPTED
    uint8_t key[ENCRYPT_KEY_SIZE];
    uint8_t nonce[ENCRYPT_NONCE_SIZE];
    uint8_t enc_blk[DELTA_BLOCK_SIZE];
#endif

    /* Use biggest size for the swap */
    total_size = boot->fw_size + IMAGE_HEADER_SIZE;
    if ((update->fw_size + IMAGE_HEADER_SIZE) > total_size)
            total_size = update->fw_size + IMAGE_HEADER_SIZE;

    hal_flash_unlock();
#ifdef EXT_FLASH
    ext_flash_unlock();
#endif
    /* Read encryption key/IV before starting the update */
#ifdef EXT_ENCRYPTED
    wolfBoot_get_encrypt_key(key, nonce);
#endif
    if (wolfBoot_get_delta_info(PART_UPDATE, inverse, &img_offset, &img_size) < 0) {
        return -1;
    }
    if (inverse) {
        uint32_t cur_v, upd_v, delta_base_v;
        cur_v = wolfBoot_current_firmware_version();
        upd_v = wolfBoot_update_firmware_version();
        delta_base_v = wolfBoot_get_diffbase_version(PART_UPDATE);
        if (((cur_v == upd_v) && (delta_base_v < cur_v)) || resume_inverse) {
            ret = wb_patch_init(&ctx, boot->hdr, boot->fw_size +
                    IMAGE_HEADER_SIZE, update->hdr + *img_offset, *img_size);
        } else {
            ret = -1;
        }
    } else {
        ret = wb_patch_init(&ctx, boot->hdr, boot->fw_size + IMAGE_HEADER_SIZE,
                update->hdr + IMAGE_HEADER_SIZE, *img_size);
    }
    if (ret < 0)
        goto out;

    while((sector * WOLFBOOT_SECTOR_SIZE) < (int)total_size) {
        if ((wolfBoot_get_update_sector_flag(sector, &flag) != 0) ||
                (flag == SECT_FLAG_NEW)) {
            uint32_t len = 0;
            wb_flash_erase(swap, 0, WOLFBOOT_SECTOR_SIZE);
            while (len < WOLFBOOT_SECTOR_SIZE) {
                ret = wb_patch(&ctx, delta_blk, DELTA_BLOCK_SIZE);
                if (ret > 0) {
#ifdef EXT_ENCRYPTED
                    uint32_t iv_counter = sector * WOLFBOOT_SECTOR_SIZE + len;
                    int wr_ret;
                    iv_counter /= ENCRYPT_BLOCK_SIZE;
                    /* Encrypt + send */
                    crypto_set_iv(nonce, iv_counter);
                    crypto_encrypt(enc_blk, delta_blk, ret);
                    wr_ret = ext_flash_write(
                            (uint32_t)(WOLFBOOT_PARTITION_SWAP_ADDRESS + len),
                            enc_blk, ret);
                    if (wr_ret < 0) {
                        ret = wr_ret;
                        goto out;
                    }
#else
                    wb_flash_write(swap, len, delta_blk, ret);
#endif
                    len += ret;
                } else if (ret == 0) {
                    break;
                } else
                    goto out;
            }
            flag = SECT_FLAG_SWAPPING;
            wolfBoot_set_update_sector_flag(sector, flag);
        } else {
            /* Consume one sector off the patched image
             * when resuming an interrupted patch
             */
            uint32_t len = 0;
            while (len < WOLFBOOT_SECTOR_SIZE) {
                ret = wb_patch(&ctx, delta_blk, DELTA_BLOCK_SIZE);
                if (ret == 0)
                    break;
                if (ret < 0)
                    goto out;
                len += ret;
            }
        }
        if (flag == SECT_FLAG_SWAPPING) {
           wolfBoot_copy_sector(swap, boot, sector);
           flag = SECT_FLAG_UPDATED;
           if (((sector + 1) * WOLFBOOT_SECTOR_SIZE) < WOLFBOOT_PARTITION_SIZE)
               wolfBoot_set_update_sector_flag(sector, flag);
        }
        if (sector == 0) {
            /* New total image size after first sector is patched */
            volatile uint32_t update_size;
            hal_flash_lock();
            update_size =
                wolfBoot_image_size((uint8_t *)WOLFBOOT_PARTITION_BOOT_ADDRESS)
                + IMAGE_HEADER_SIZE;
            hal_flash_unlock();
            if (update_size > total_size)
                total_size = update_size;
            if (total_size <= IMAGE_HEADER_SIZE) {
                ret = -1;
                goto out;
            }
            if (total_size > WOLFBOOT_PARTITION_SIZE) {
                ret = -1;
                goto out;
            }

        }
        sector++;
    }
    ret = 0;
    while((sector * WOLFBOOT_SECTOR_SIZE) < WOLFBOOT_PARTITION_SIZE) {
        hal_flash_erase(WOLFBOOT_PARTITION_BOOT_ADDRESS +
                sector * WOLFBOOT_SECTOR_SIZE, WOLFBOOT_SECTOR_SIZE);
        sector++;
    }
    st = IMG_STATE_TESTING;
    wolfBoot_set_partition_state(PART_BOOT, st);
    /* On success, reset all flags on update partition */
    wb_flash_erase(update, WOLFBOOT_PARTITION_SIZE - WOLFBOOT_SECTOR_SIZE,
            WOLFBOOT_SECTOR_SIZE);
out:
    wb_flash_erase(swap, 0, WOLFBOOT_SECTOR_SIZE);
#ifdef EXT_FLASH
    ext_flash_lock();
#endif
    hal_flash_lock();

/* Save the encryption key after swapping */
#ifdef EXT_ENCRYPTED
    wolfBoot_set_encrypt_key(key, nonce);
#endif
    return ret;
}

#endif


#ifdef WOLFBOOT_ARMORED
#    pragma GCC push_options
#    pragma GCC optimize("O0")
#endif

/* Reserve space for two sectors in case of NVM_FLASH_WRITEONCE, for redundancy */
#ifndef NVM_FLASH_WRITEONCE
    #define MAX_UPDATE_SIZE (size_t)((WOLFBOOT_PARTITION_SIZE - WOLFBOOT_SECTOR_SIZE))
#else
    #define MAX_UPDATE_SIZE (size_t)((WOLFBOOT_PARTITION_SIZE - (2 *WOLFBOOT_SECTOR_SIZE)))
#endif

static int RAMFUNCTION wolfBoot_update(int fallback_allowed)
{
    uint32_t total_size = 0;
    const uint32_t sector_size = WOLFBOOT_SECTOR_SIZE;
    uint32_t sector = 0;
    uint8_t flag, st;
    struct wolfBoot_image boot, update, swap;
    uint16_t update_type;
#ifdef EXT_ENCRYPTED
    uint8_t key[ENCRYPT_KEY_SIZE];
    uint8_t nonce[ENCRYPT_NONCE_SIZE];
#endif
#ifdef DELTA_UPDATES
    int inverse = 0;
    int inverse_resume = 0;
    uint32_t cur_v;
    uint32_t up_v;
#endif

    /* No Safety check on open: we might be in the middle of a broken update */
    wolfBoot_open_image(&update, PART_UPDATE);
    wolfBoot_open_image(&boot, PART_BOOT);
    wolfBoot_open_image(&swap, PART_SWAP);

    /* Use biggest size for the swap */
    total_size = boot.fw_size + IMAGE_HEADER_SIZE;
    if ((update.fw_size + IMAGE_HEADER_SIZE) > total_size)
            total_size = update.fw_size + IMAGE_HEADER_SIZE;

    if (total_size <= IMAGE_HEADER_SIZE)
        return -1;
    /* In case this is a new update, do the required
     * checks on the firmware update
     * before starting the swap
     */

    update_type = wolfBoot_get_image_type(PART_UPDATE);

    /* Check the first sector to detect interrupted update */
    if ((wolfBoot_get_update_sector_flag(0, &flag) < 0) ||
            (flag == SECT_FLAG_NEW))
    {
        if (((update_type & 0x000F) != HDR_IMG_TYPE_APP) ||
                ((update_type & 0xFF00) != HDR_IMG_TYPE_AUTH))
            return -1;
        if (update.fw_size > MAX_UPDATE_SIZE - 1)
            return -1;
        if (!update.hdr_ok || (wolfBoot_verify_integrity(&update) < 0)
                || (wolfBoot_verify_authenticity(&update) < 0)) {
            return -1;
        }
        PART_SANITY_CHECK(&update);
#ifndef ALLOW_DOWNGRADE
        if ( ((fallback_allowed==1) && 
                    (~(uint32_t)fallback_allowed == 0xFFFFFFFE)) ||
                (wolfBoot_current_firmware_version() <
                 wolfBoot_update_firmware_version()) ) {
            VERIFY_VERSION_ALLOWED(fallback_allowed);
        } else
            return -1;
#endif
    }


#ifdef DELTA_UPDATES
    if ((update_type & 0x00F0) == HDR_IMG_TYPE_DIFF) {
        cur_v = wolfBoot_current_firmware_version();
        up_v = wolfBoot_update_firmware_version();
        inverse = cur_v >= up_v;

        /* if the first sector flag is not new but we are updating then */
        /* we were interrupted */
        if (flag != SECT_FLAG_NEW &&
            wolfBoot_get_partition_state(PART_UPDATE, &st) == 0 &&
            st == IMG_STATE_UPDATING) {
            if (cur_v == up_v) {
                inverse = 0;
            }
            else if (cur_v < up_v) {
                inverse = 1;
                inverse_resume = 1;
            }
        }

        return wolfBoot_delta_update(&boot, &update, &swap, inverse,
            inverse_resume);
    }
#endif

    hal_flash_unlock();
#ifdef EXT_FLASH
    ext_flash_unlock();
#endif


/* Read encryption key/IV before starting the update */
#ifdef EXT_ENCRYPTED
    wolfBoot_get_encrypt_key(key, nonce);
#endif

#ifndef DISABLE_BACKUP
    /* Interruptible swap
     * The status is saved in the sector flags of the update partition.
     * If something goes wrong, the operation will be resumed upon reboot.
     */
    while ((sector * sector_size) < total_size) {
        if ((wolfBoot_get_update_sector_flag(sector, &flag) != 0) || (flag == SECT_FLAG_NEW)) {
           flag = SECT_FLAG_SWAPPING;
           wolfBoot_copy_sector(&update, &swap, sector);
           if (((sector + 1) * sector_size) < WOLFBOOT_PARTITION_SIZE)
               wolfBoot_set_update_sector_flag(sector, flag);
        }
        if (flag == SECT_FLAG_SWAPPING) {
            uint32_t size = total_size - (sector * sector_size);
            if (size > sector_size)
                size = sector_size;
            flag = SECT_FLAG_BACKUP;
            wolfBoot_copy_sector(&boot, &update, sector);
           if (((sector + 1) * sector_size) < WOLFBOOT_PARTITION_SIZE)
                wolfBoot_set_update_sector_flag(sector, flag);
        }
        if (flag == SECT_FLAG_BACKUP) {
            uint32_t size = total_size - (sector * sector_size);
            if (size > sector_size)
                size = sector_size;
            flag = SECT_FLAG_UPDATED;
            wolfBoot_copy_sector(&swap, &boot, sector);
            if (((sector + 1) * sector_size) < WOLFBOOT_PARTITION_SIZE)
                wolfBoot_set_update_sector_flag(sector, flag);
        }
        sector++;
    }
    while((sector * sector_size) < WOLFBOOT_PARTITION_SIZE) {
        wb_flash_erase(&boot, sector * sector_size, sector_size);
        wb_flash_erase(&update, sector * sector_size, sector_size);
        sector++;
    }
    wb_flash_erase(&swap, 0, WOLFBOOT_SECTOR_SIZE);
    st = IMG_STATE_TESTING;
    wolfBoot_set_partition_state(PART_BOOT, st);
#else /* DISABLE_BACKUP */
#warning "Backup mechanism disabled! Update installation will not be interruptible"
    /* Directly copy the content of the UPDATE partition into the BOOT partition.
     * This mechanism is not fail-safe, and will brick your device if interrupted
     * before the copy is finished.
     */
    while ((sector * sector_size) < total_size) {
        if ((wolfBoot_get_update_sector_flag(sector, &flag) != 0) || (flag == SECT_FLAG_NEW)) {
           flag = SECT_FLAG_SWAPPING;
           wolfBoot_copy_sector(&update, &boot, sector);
           if (((sector + 1) * sector_size) < WOLFBOOT_PARTITION_SIZE)
               wolfBoot_set_update_sector_flag(sector, flag);
        }
        sector++;
    }
    while((sector * sector_size) < WOLFBOOT_PARTITION_SIZE) {
        wb_flash_erase(&boot, sector * sector_size, sector_size);
        sector++;
    }
    st = IMG_STATE_SUCCESS;
    wolfBoot_set_partition_state(PART_BOOT, st);
#endif

#if defined(WOLFBOOT_TPM) && defined(WOLFTPM_KEYSTORE)
    /* reseal the true pubkey after the image update */
    if (wolfBoot_reseal_keys(&boot, &update) != 0)
        return -1;
#endif

#ifdef EXT_FLASH
    ext_flash_lock();
#endif
    hal_flash_lock();

/* Save the encryption key after swapping */
#ifdef EXT_ENCRYPTED
    wolfBoot_set_encrypt_key(key, nonce);
#endif
    return 0;
}

int wantReload = 1;
int flashUnlocked = 0;

/* TODO enum might not be wise, need properly unchangable steps */
enum Step {
    CHECK_BOOT_STATE,
    CHECK_UPDATE_STATE,
    VERIFY_BOOT,
    VERIFY_UPDATE,
    COPY_UPDATE_TO_SWAP,
    COPY_BOOT_TO_UPDATE,
    COPY_SWAP_TO_BOOT,
    ERASE_REMAINDER,
    DO_BOOT
};

struct UpdateState {
    uint32_t sector;
    uint32_t sectorSize;
    uint32_t totalSize;
    uint8_t fallbackAllowed;
#ifdef EXT_ENCRYPTED
    uint8_t key[ENCRYPT_KEY_SIZE];
    uint8_t nonce[ENCRYPT_NONCE_SIZE];
#endif
#ifdef DELTA_UPDATES
    WB_PATCH_CTX deltaCtx[1];
    int inverse;
    uint32_t consumedSector;
    uint16_t deltaImgSize;
    uint32_t deltaImgOffset;
#endif
};

int RAMFUNCTION findStep()
{
    int step;

    /* verify and read what step we left off on */
    step = readStep();

    /* no step found, check boot state */
    if (step < 0)
        step = CHECK_BOOT_STATE;

    return step;
}

int checkBootState(struct UpdateState* updateState)
{
    uint8_t st;

    if ((wolfBoot_get_partition_state(PART_BOOT, &st) == 0) &&
        (st == IMG_STATE_TESTING)) {
        /* this function is fine, it just sets update to testing */
        /* which is repeatable */
        wolfBoot_update_trigger();
        /* since we booted into testing state, fallback to update */
        updateState->fallbackAllowed = 1;

        return VERIFY_UPDATE;
    }

    return CHECK_UPDATE_STATE;
}

int checkUpdateState(struct UpdateState* updateState)
{
    uint8_t st;

    if ((wolfBoot_get_partition_state(PART_UPDATE, &st) == 0) &&
        (st == IMG_STATE_UPDATING)) {
        /* this has to be set explicitly to avoid an junk value being 1 */
        updateState->fallbackAllowed = 0;

        return VERIFY_UPDATE;
    }

    return VERIFY_BOOT;
}

int verifyBoot(struct wolfBoot_image* boot, struct UpdateState* updateState)
{
    int step;

    if ((wolfBoot_verify_integrity(boot) < 0)
        || (wolfBoot_verify_authenticity(boot) < 0)) {
        /* try to update, this can happen forever */
        updateState->fallbackAllowed = 1;
        return VERIFY_UPDATE;
    }

    return DO_BOOT;
}

int verifyUpdate(struct wolfBoot_image* boot, struct wolfBoot_image* update,
    struct UpdateState* updateState)
{
    uint16_t updateType;
    uint32_t currentVersion;
    uint32_t updateVersion;

    currentVersion = wolfBoot_current_firmware_version();
    updateVersion = wolfBoot_update_firmware_version();

    updateType = wolfBoot_get_image_type(PART_UPDATE);

    if (
        /* update type is app or auth */
        (updateType & 0x000F) != HDR_IMG_TYPE_APP ||
        (updateType & 0xFF00) != HDR_IMG_TYPE_AUTH ||
        /* update size is within max */
        update->fw_size > MAX_UPDATE_SIZE - 1 ||
        /* hdr is valid */
        !update->hdr_ok ||
#ifndef ALLOW_DOWNGRADE
        /* were upgrading or are allowed to fallback */
        (updateState->fallbackAllowed == 0 &&
        currentVersion >= updateVersion) ||
#endif
#ifdef DELTA_UPDATES
        /* update has diff type */
        (updateType & 0x00F0) != HDR_IMG_TYPE_DIFF ||
#endif
        /* update digest and signature are valid */
        wolfBoot_verify_integrity(update) < 0 ||
        wolfBoot_verify_authenticity(update) < 0
    ) {
        /* try to boot, this can happen forever */
        return VERIFY_BOOT;
    }

    PART_SANITY_CHECK(update);

#ifndef ALLOW_DOWNGRADE
    /* double check if we're falling back */
    if (updateState->fallbackAllowed == 1) {
        VERIFY_VERSION_ALLOWED(updateState->fallbackAllowed);
    }
#endif

    /* set the sector to 0 */
    updateState->sector = 0;
#ifdef DELTA_UPDATES
    updateState->consumedSector = 0;
#endif
    updateState->sectorSize = WOLFBOOT_SECTOR_SIZE;

    /* use the larger of the two images for the total size */
    updateState->totalSize = boot->fw_size + IMAGE_HEADER_SIZE;
    if ((update->fw_size + IMAGE_HEADER_SIZE) > 
        updateState->totalSize) {
        updateState->totalSize = update->fw_size + IMAGE_HEADER_SIZE;
    }

    /* if we have inconsistent headers panic */
    if (updateState->totalSize <= IMAGE_HEADER_SIZE)
        return -1;

    return COPY_UPDATE_TO_SWAP;
}

int copySwapToBoot(struct wolfBoot_image* boot, struct wolfBoot_image* update,
    struct wolfBoot_image* swap, struct UpdateState* updateState)
{
    uint32_t fwSwap;

    /* repeatable without consequence */
    wolfBoot_copy_sector(swap, boot, updateState->sector);

    /* increment sector */
    updateState->sector++;

    /* check if there's more sectors to copy */
    if ((updateState->sector * updateState->sectorSize) <
        updateState->totalSize) {
        /* handle the case where the boot and update headers have swapped,
         * meaning the address of boot and update are correct but the
         * fw_size is swapped, may have already been handled at startup */
        if (wantReload == 1) {
            /* reopen with headers in a known good state */
            wolfBoot_open_image(boot, PART_BOOT);
            wolfBoot_open_image(update, PART_UPDATE);
            wolfBoot_open_image(swap, PART_SWAP);

            fwSwap = boot->fw_size;
            boot->fw_size = update->fw_size;
            update->fw_size = fwSwap;

            wantReload = 0;
        }

        return COPY_UPDATE_TO_SWAP;
    }

    /* otherwise erase the remainder */
    return ERASE_REMAINDER;
}

int eraseRemainder(struct wolfBoot_image* boot, struct wolfBoot_image* update,
    struct wolfBoot_image* swap, struct UpdateState* updateState)
{
    uint8_t st;

    /* repeatable without consequence */
    while((updateState->sector * updateState->sectorSize) <
        WOLFBOOT_PARTITION_SIZE) {
        wb_flash_erase(boot, updateState->sector *
            updateState->sectorSize, updateState->sectorSize);
#ifndef DELTA_UPDATES
        wb_flash_erase(update, updateState->sector *
            updateState->sectorSize, updateState->sectorSize);
#endif
        updateState->sector++;
    }

    wb_flash_erase(swap, 0, WOLFBOOT_SECTOR_SIZE);

    st = IMG_STATE_TESTING;
    wolfBoot_set_partition_state(PART_BOOT, st);

    /* lock flash */
#ifdef EXT_FLASH
    ext_flash_lock();
#endif
    hal_flash_lock();

    flashUnlocked = 0;
#ifdef EXT_ENCRYPTED
    wolfBoot_set_encrypt_key(updateState->key, updateState->nonce);
#endif
#ifndef DELTA_UPDATES
    deltaInited = 0;
#endif

    return VERIFY_BOOT;
}

void flashUnlock(struct UpdateState* updateState)
{
    if (flashUnlocked == 0) {
        hal_flash_unlock();
#ifdef EXT_FLASH
        ext_flash_unlock();
#endif
#ifdef EXT_ENCRYPTED
        wolfBoot_get_encrypt_key(updateState->key, updateState->nonce);
#endif
        flashUnlocked = 1;
    }

    (void)updateState;
}

#ifdef DELTA_UPDATES
int deltaInited = 0;

int deltaInit(struct wolfBoot_image* boot, struct wolfBoot_image* update,
    struct UpdateState* updateState, int step)
{
    int ret = 0;
    uint32_t currentVersion;
    uint32_t updateVersion;
    uint32_t deltaBaseVersion;
    uint32_t* deltaImgOffset;
    uint16_t* deltaImgSize;
    uint32_t sector = 0;
    uint32_t len = 0;
    uint8_t delta_blk[DELTA_BLOCK_SIZE];

    if (deltaInited == 0) {
        /* initialize the delta state */
        /* uses pointers so should not be used from flash */
        currentVersion = wolfBoot_current_firmware_version();
        updateVersion = wolfBoot_update_firmware_version();
        deltaBaseVersion = wolfBoot_get_diffbase_version(PART_UPDATE);

        ret = wolfBoot_get_delta_info(PART_UPDATE,
            currentVersion >= updateVersion, &deltaImgOffset, &deltaImgSize);

        if (ret != 0)
            return ret;

        /* I don't know the details of how delta computes this information but
         * deltaImgSize can change after a power failure, save off the original
         * deltaImgSize */
        if (updateState->consumedSector == 0)
            updateState->deltaImgSize = *deltaImgSize;

        /* inverse */
        /* only rely on version when consumedSector is 0 and we haven't
         * overwritten the boot header, otherwise use updateState */
        if ((updateState->consumedSector == 0 &&
            currentVersion == updateVersion &&
            deltaBaseVersion < currentVersion) ||
            updateState->inverse == 1) {
            if (deltaImgOffset != NULL)
                updateState->deltaImgOffset = *deltaImgOffset;

            ret = wb_patch_init(updateState->deltaCtx, boot->hdr,
                boot->fw_size + IMAGE_HEADER_SIZE, update->hdr +
                updateState->deltaImgOffset, updateState->deltaImgSize);
            updateState->inverse = 1;
        }
        /* normal */
        else {
            ret = wb_patch_init(updateState->deltaCtx, boot->hdr,
                boot->fw_size + IMAGE_HEADER_SIZE, update->hdr +
                IMAGE_HEADER_SIZE, updateState->deltaImgSize);
            updateState->inverse = 0;
        }

        if (ret != 0)
            return ret;

        /* consume sectors until we're caught up */
        while (sector < updateState->consumedSector) {
            len = 0;

            while (len < WOLFBOOT_SECTOR_SIZE) {
                ret = wb_patch(updateState->deltaCtx, delta_blk,
                    DELTA_BLOCK_SIZE);
                if (ret == 0)
                    break;
                if (ret < 0)
                    return ret;
                len += ret;
            }

            sector++;
        }

        ret = 0;
        deltaInited = 1;

        /* need to save since we set updateState->inverse here */
        saveStep(step, (uint8_t*)updateState, sizeof(struct UpdateState));
    }

    return ret;
}

int deltaCopyUpdateToSwap(struct wolfBoot_image* update,
    struct wolfBoot_image* swap, struct UpdateState* updateState)
{
    int ret = -1;
    uint32_t len = 0;
    uint8_t delta_blk[DELTA_BLOCK_SIZE];

    wb_flash_erase(swap, 0, WOLFBOOT_SECTOR_SIZE);

    while (len < WOLFBOOT_SECTOR_SIZE) {
        ret = wb_patch(updateState->deltaCtx, delta_blk, DELTA_BLOCK_SIZE);

        if (ret > 0) {
#ifdef EXT_ENCRYPTED
            uint8_t enc_blk[DELTA_BLOCK_SIZE];
            uint32_t iv_counter = updateState->sector * WOLFBOOT_SECTOR_SIZE + len;
            int wr_ret;

            iv_counter /= ENCRYPT_BLOCK_SIZE;
            /* Encrypt + send */
            crypto_set_iv(updateState->nonce, iv_counter);
            crypto_encrypt(enc_blk, delta_blk, ret);
            wr_ret = ext_flash_write(
                    (uint32_t)(WOLFBOOT_PARTITION_SWAP_ADDRESS + len),
                    enc_blk, ret);
            if (wr_ret < 0) {
                ret = wr_ret;
                return -1;
            }
#else
            wb_flash_write(swap, len, delta_blk, ret);
#endif
            len += ret;
        } else if (ret == 0) {
            break;
        } else
            return -1;
    }

    updateState->consumedSector++;

    return COPY_SWAP_TO_BOOT;
}

int deltaCopySwapToBoot(struct wolfBoot_image* swap,
    struct wolfBoot_image* boot, struct UpdateState* updateState)
{
    wolfBoot_copy_sector(swap, boot, updateState->sector);

    if (updateState->sector == 0) {
        /* New total image size after first sector is patched */
        volatile uint32_t updateSize;

        hal_flash_lock();
        updateSize =
            wolfBoot_image_size((uint8_t *)WOLFBOOT_PARTITION_BOOT_ADDRESS)
            + IMAGE_HEADER_SIZE;
        hal_flash_unlock();
        if (updateSize > updateState->totalSize)
            updateState->totalSize = updateSize;
        if (updateState->totalSize <= IMAGE_HEADER_SIZE) {
            return -1;
        }
        if (updateState->totalSize > WOLFBOOT_PARTITION_SIZE) {
            return -1;
        }
    }

    updateState->sector++;

    /* copy next sector if we're not at the end */
    if ((updateState->sector * WOLFBOOT_SECTOR_SIZE) <
        updateState->totalSize) {
        return COPY_UPDATE_TO_SWAP;
    }
    /* otherwise erase the remainder */
    /* reset consumedSector in case we fallback */
    updateState->consumedSector = 0;

    return ERASE_REMAINDER;
}
#endif /* DELTA_UPDATES */

static void RAMFUNCTION printStep(int step)
{
    switch (step) {
        case CHECK_BOOT_STATE:
            //wolfBoot_printf("CHECK_BOOT_STATE\n");
            break;
        case CHECK_UPDATE_STATE:
            //wolfBoot_printf("CHECK_UPDATE_STATE\n");
            break;
        case VERIFY_BOOT:
            //wolfBoot_printf("VERIFY_BOOT\n");
            break;
        case VERIFY_UPDATE:
            //wolfBoot_printf("VERIFY_UPDATE\n");
            break;
        case COPY_UPDATE_TO_SWAP:
            //wolfBoot_printf("COPY_UPDATE_TO_SWAP\n");
            break;
        case COPY_BOOT_TO_UPDATE:
            //wolfBoot_printf("COPY_BOOT_TO_UPDATE\n");
            break;
        case COPY_SWAP_TO_BOOT:
            //wolfBoot_printf("COPY_SWAP_TO_BOOT\n");
            break;
        case ERASE_REMAINDER:
            //wolfBoot_printf("ERASE_REMAINDER\n");
            break;
        case DO_BOOT:
            //wolfBoot_printf("DO_BOOT\n");
            break;
        default:
            //wolfBoot_printf("UNKNOWN\n");
            break;
    }
}

void RAMFUNCTION wolfBoot_start(void)
{
    int step;
    struct wolfBoot_image boot[1];
    struct wolfBoot_image update[1];
    struct wolfBoot_image swap[1];
    struct UpdateState updateState[1];

#ifdef RAM_CODE
    wolfBoot_check_self_update();
#endif

    step = findStep();

    /* load the images, boot process should assume they're invalid since
     * we may be resuming */
    wolfBoot_open_image(boot, PART_BOOT);
    wolfBoot_open_image(update, PART_UPDATE);
    wolfBoot_open_image(swap, PART_SWAP);

    /* read and repeatable actions only, save state after each action */
    while (step >= 0) {
        /* load the state, can be junk if not explicitly set and saved */
        /* will be verified by findStep until cleared by clearSteps */
        loadState((uint8_t*)updateState, sizeof(struct UpdateState));

        /* printStep(step); */

        switch (step) {
            case CHECK_BOOT_STATE:
                step = checkBootState(updateState);
                break;
            case CHECK_UPDATE_STATE:
                step = checkUpdateState(updateState);
                break;
            case VERIFY_BOOT:
                /* this needs to be re-run since the first partition of boot
                 * can be invalid at the start */
                wolfBoot_open_image(boot, PART_BOOT);
                wolfBoot_open_image(update, PART_UPDATE);
                wolfBoot_open_image(swap, PART_SWAP);

                step = verifyBoot(boot, updateState);
                break;
            case VERIFY_UPDATE:
                wolfBoot_open_image(boot, PART_BOOT);
                wolfBoot_open_image(update, PART_UPDATE);
                wolfBoot_open_image(swap, PART_SWAP);

                step = verifyUpdate(boot, update, updateState);
                break;
            case COPY_UPDATE_TO_SWAP:
                /* unlock flash and possibly ext_flash */
                flashUnlock(updateState);
#ifdef DELTA_UPDATES
                /* init deltaCtx if not done yet */
                step = deltaInit(boot, update, updateState, step);

                if (step == 0)
                    step = deltaCopyUpdateToSwap(update, swap, updateState);
#else
                /* repeatable without consequence */
                wolfBoot_copy_sector(update, swap, updateState->sector);

                step = COPY_BOOT_TO_UPDATE;
#endif
                break;
            case COPY_BOOT_TO_UPDATE:
                /* unlock flash and possibly ext_flash */
                flashUnlock(updateState);

                /* repeatable without consequence */
                wolfBoot_copy_sector(boot, update, updateState->sector);

                step = COPY_SWAP_TO_BOOT;
                break;
            case COPY_SWAP_TO_BOOT:
                /* unlock flash and possibly ext_flash */
                flashUnlock(updateState);
#ifdef DELTA_UPDATES
                /* init deltaCtx if not done yet */
                step = deltaInit(boot, update, updateState, step);

                if (step == 0)
                    step = deltaCopySwapToBoot(swap, boot, updateState);
#else
                step = copySwapToBoot(boot, update, swap, updateState);
#endif
                /* headers are in a known good state, reload and swap fw_size */
                break;
            case ERASE_REMAINDER:
                step = eraseRemainder(boot, update, swap, updateState);
                break;
            case DO_BOOT:
                PART_SANITY_CHECK(boot);

                hal_prepare_boot();
                do_boot((void *)(boot->fw_base));
                break;
            default:
                clearSteps();
                wolfBoot_panic();
                break;
        }

        /* if we're about to boot clear the steps to get a clean reboot */
        if (step == DO_BOOT)
            clearSteps();
        /* if step is valid */
        else if (step >= 0)
            saveStep(step, (uint8_t*)updateState, sizeof(updateState));
    }

    clearSteps();
    wolfBoot_panic();
}
#ifdef WOLFBOOT_ARMORED
#    pragma GCC pop_options
#endif
