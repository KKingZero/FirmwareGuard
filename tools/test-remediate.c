#include "../include/firmwareguard.h"
#include "../src/safety/safety.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void write_file(const char *path, const char *data) {
    FILE *fp = fopen(path, "wb");
    assert(fp != NULL);
    assert(fwrite(data, 1, strlen(data), fp) == strlen(data));
    fclose(fp);
}

static void read_file(const char *path, char *buf, size_t size) {
    FILE *fp = fopen(path, "rb");
    size_t n;

    assert(fp != NULL);
    n = fread(buf, 1, size - 1, fp);
    buf[n] = '\0';
    fclose(fp);
}

static void init_test_ctx(safety_context_t *ctx, const char *backup_dir,
                          safety_mode_t mode) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->mode = mode;
    ctx->dry_run = (mode == SAFETY_MODE_DRY_RUN);
    ctx->require_confirmation = false;
    snprintf(ctx->registry.backup_dir, sizeof(ctx->registry.backup_dir),
             "%s", backup_dir);
}

int main(void) {
    char dir_template[] = "/tmp/fg-remediate-XXXXXX";
    char *dir = mkdtemp(dir_template);
    char backup_dir[512];
    char grub_path[512];
    char buf[256];
    safety_context_t ctx;
    const char *original = "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n";
    const char *changed = "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet intel_iommu=on\"\n";

    assert(dir != NULL);
    snprintf(backup_dir, sizeof(backup_dir), "%s/backups", dir);
    snprintf(grub_path, sizeof(grub_path), "%s/grub", dir);
    assert(mkdir(backup_dir, 0700) == 0);

    setenv("FG_TEST_GRUB_FILE", grub_path, 1);
    setenv("FG_TEST_SKIP_GRUB_UPDATE", "1", 1);

    write_file(grub_path, original);
    init_test_ctx(&ctx, backup_dir, SAFETY_MODE_AUTO);
    assert(safety_create_backup(&ctx, BACKUP_TYPE_GRUB_CONFIG,
                                "grub_default", original,
                                strlen(original)) == FG_SUCCESS);
    write_file(grub_path, changed);
    assert(safety_restore_backup(&ctx, &ctx.registry.backups[0]) == FG_SUCCESS);
    read_file(grub_path, buf, sizeof(buf));
    assert(strcmp(buf, original) == 0);

    write_file(grub_path, changed);
    init_test_ctx(&ctx, backup_dir, SAFETY_MODE_DRY_RUN);
    ctx.registry.num_backups = 1;
    ctx.registry.backups[0].type = BACKUP_TYPE_GRUB_CONFIG;
    ctx.registry.backups[0].valid = true;
    snprintf(ctx.registry.backups[0].name, sizeof(ctx.registry.backups[0].name),
             "grub_default");
    snprintf(ctx.registry.backups[0].backup_path,
             sizeof(ctx.registry.backups[0].backup_path),
             "%s/grub_default_test.bak", backup_dir);
    safety_calculate_hash(original, strlen(original),
                          ctx.registry.backups[0].checksum);
    write_file(ctx.registry.backups[0].backup_path, original);
    assert(safety_restore_backup(&ctx, &ctx.registry.backups[0]) == FG_SUCCESS);
    read_file(grub_path, buf, sizeof(buf));
    assert(strcmp(buf, changed) == 0);

    printf("test-remediate: PASS\n");
    return 0;
}
