#include "grub_config.h"
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

int grub_init(grub_config_t *config) {
    struct stat st;

    if (!config) {
        return FG_ERROR;
    }

    memset(config, 0, sizeof(grub_config_t));

    /* Detect GRUB installation */
    if (stat("/etc/default/grub", &st) == 0) {
        config->grub_exists = true;
        strncpy(config->grub_file, "/etc/default/grub",
                sizeof(config->grub_file) - 1);
    } else if (stat("/etc/default/grub2", &st) == 0) {
        config->grub2_exists = true;
        strncpy(config->grub_file, "/etc/default/grub2",
                sizeof(config->grub_file) - 1);
    } else {
        FG_WARN("GRUB configuration not found");
        return FG_NOT_FOUND;
    }

    FG_INFO("GRUB subsystem initialized (config: %s)", config->grub_file);
    return FG_SUCCESS;
}

void grub_cleanup(grub_config_t *config) {
    if (config) {
        memset(config, 0, sizeof(grub_config_t));
    }
}

int grub_read_config(grub_config_t *config) {
    FILE *fp;
    char line[1024];
    char *ptr;

    if (!config || !config->grub_exists) {
        return FG_ERROR;
    }

    fp = fopen(config->grub_file, "r");
    if (!fp) {
        FG_LOG_ERROR("Failed to open GRUB config: %s", config->grub_file);
        return FG_NO_PERMISSION;
    }

    /* Parse GRUB_CMDLINE_LINUX_DEFAULT */
    while (fgets(line, sizeof(line), fp)) {
        /* Remove newline */
        line[strcspn(line, "\n")] = 0;

        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        /* Look for GRUB_CMDLINE_LINUX_DEFAULT */
        if (strncmp(line, "GRUB_CMDLINE_LINUX_DEFAULT=", 27) == 0) {
            ptr = line + 27;

            /* Remove quotes */
            if (*ptr == '"') {
                ptr++;
                char *end = strrchr(ptr, '"');
                if (end) {
                    *end = '\0';
                }
            }

            strncpy(config->cmdline_linux_default, ptr,
                   sizeof(config->cmdline_linux_default) - 1);
            break;
        }
    }

    fclose(fp);

    FG_DEBUG("Current GRUB_CMDLINE_LINUX_DEFAULT: %s",
             config->cmdline_linux_default);

    return FG_SUCCESS;
}

int grub_backup_config(safety_context_t *safety_ctx) {
    FILE *fp;
    struct stat st;
    void *data;
    size_t size;
    int ret;

    if (!safety_ctx) {
        return FG_ERROR;
    }

    if (safety_is_dry_run(safety_ctx)) {
        FG_INFO("[DRY-RUN] Would backup GRUB configuration");
        return FG_SUCCESS;
    }

    /* Read entire GRUB config file */
    if (stat(GRUB_DEFAULT_FILE, &st) != 0) {
        FG_LOG_ERROR("GRUB config file not found: %s", GRUB_DEFAULT_FILE);
        return FG_NOT_FOUND;
    }

    /* Validate size before allocation */
    if (st.st_size <= 0) {
        FG_LOG_ERROR("Invalid GRUB config file size: %ld", (long)st.st_size);
        return FG_ERROR;
    }

    /* GRUB config shouldn't be more than 1MB */
    if (st.st_size > (1024 * 1024)) {
        FG_LOG_ERROR("GRUB config file too large: %ld bytes", (long)st.st_size);
        return FG_ERROR;
    }

    size = (size_t)st.st_size;
    data = malloc(size);
    if (!data) {
        return FG_ERROR;
    }

    fp = fopen(GRUB_DEFAULT_FILE, "rb");
    if (!fp) {
        free(data);
        return FG_ERROR;
    }

    if (fread(data, 1, size, fp) != size) {
        FG_LOG_ERROR("Failed to read GRUB config");
        fclose(fp);
        free(data);
        return FG_ERROR;
    }

    fclose(fp);

    /* Create backup */
    ret = safety_create_backup(safety_ctx, BACKUP_TYPE_GRUB_CONFIG,
                               "grub_default", data, size);

    free(data);
    return ret;
}

bool grub_has_kernel_param(const grub_config_t *config, const char *param) {
    if (!config || !param) {
        return false;
    }

    return (strstr(config->cmdline_linux_default, param) != NULL);
}

int grub_add_kernel_param(safety_context_t *safety_ctx,
                          grub_config_t *config,
                          const char *param) {
    char new_cmdline[1024];

    if (!config || !param) {
        return FG_ERROR;
    }

    /* Validate param to prevent command injection */
    if (strchr(param, ';') || strchr(param, '&') || strchr(param, '|') ||
        strchr(param, '`') || strchr(param, '$') || strchr(param, '\n')) {
        FG_LOG_ERROR("Invalid kernel parameter (contains dangerous characters)");
        return FG_ERROR;
    }

    /* Check if already present */
    if (grub_has_kernel_param(config, param)) {
        FG_INFO("Kernel parameter already present: %s", param);
        return FG_SUCCESS;
    }

    if (safety_ctx && safety_is_dry_run(safety_ctx)) {
        FG_INFO("[DRY-RUN] Would add kernel parameter: %s", param);
        return FG_SUCCESS;
    }

    /* Append parameter */
    int ret;
    if (strlen(config->cmdline_linux_default) > 0) {
        ret = snprintf(new_cmdline, sizeof(new_cmdline), "%s %s",
                      config->cmdline_linux_default, param);
    } else {
        ret = snprintf(new_cmdline, sizeof(new_cmdline), "%s", param);
    }

    /* Check for truncation */
    if (ret < 0 || ret >= (int)sizeof(new_cmdline)) {
        FG_LOG_ERROR("Kernel cmdline too long (would be %d bytes, max: %zu)",
                     ret, sizeof(new_cmdline) - 1);
        return FG_ERROR;
    }

    strncpy(config->cmdline_linux_default, new_cmdline,
            sizeof(config->cmdline_linux_default) - 1);
    config->is_modified = true;

    FG_INFO("Added kernel parameter: %s", param);
    return FG_SUCCESS;
}

int grub_remove_kernel_param(safety_context_t *safety_ctx,
                             grub_config_t *config,
                             const char *param) {
    char new_cmdline[1024];
    char *found;

    if (!config || !param) {
        return FG_ERROR;
    }

    /* Check if parameter exists */
    found = strstr(config->cmdline_linux_default, param);
    if (!found) {
        FG_INFO("Kernel parameter not present: %s", param);
        return FG_SUCCESS;
    }

    if (safety_ctx && safety_is_dry_run(safety_ctx)) {
        FG_INFO("[DRY-RUN] Would remove kernel parameter: %s", param);
        return FG_SUCCESS;
    }

    /* Build new cmdline without the parameter */
    *found = '\0';
    snprintf(new_cmdline, sizeof(new_cmdline), "%s%s",
             config->cmdline_linux_default,
             found + strlen(param));

    /* Remove trailing/leading spaces */
    char *p = new_cmdline;
    while (*p && *p == ' ') p++;
    memmove(new_cmdline, p, strlen(p) + 1);

    p = new_cmdline + strlen(new_cmdline) - 1;
    while (p > new_cmdline && *p == ' ') {
        *p = '\0';
        p--;
    }

    strncpy(config->cmdline_linux_default, new_cmdline,
            sizeof(config->cmdline_linux_default) - 1);
    config->is_modified = true;

    FG_INFO("Removed kernel parameter: %s", param);
    return FG_SUCCESS;
}

int grub_write_config(safety_context_t *safety_ctx,
                      const grub_config_t *config) {
    FILE *fp_in, *fp_out;
    char line[1024];
    char temp_file[256];
    bool replaced = false;

    if (!config || !config->is_modified) {
        return FG_SUCCESS;
    }

    if (safety_ctx && safety_is_dry_run(safety_ctx)) {
        FG_INFO("[DRY-RUN] Would write GRUB configuration");
        return FG_SUCCESS;
    }

    /* Create temporary file */
    snprintf(temp_file, sizeof(temp_file), "%s.tmp", config->grub_file);

    fp_in = fopen(config->grub_file, "r");
    if (!fp_in) {
        FG_LOG_ERROR("Failed to open GRUB config for reading");
        return FG_ERROR;
    }

    fp_out = fopen(temp_file, "w");
    if (!fp_out) {
        FG_LOG_ERROR("Failed to create temporary file");
        fclose(fp_in);
        return FG_ERROR;
    }

    /* Copy file, replacing GRUB_CMDLINE_LINUX_DEFAULT */
    while (fgets(line, sizeof(line), fp_in)) {
        if (strncmp(line, "GRUB_CMDLINE_LINUX_DEFAULT=", 27) == 0) {
            fprintf(fp_out, "GRUB_CMDLINE_LINUX_DEFAULT=\"%s\"\n",
                    config->cmdline_linux_default);
            replaced = true;
        } else {
            fputs(line, fp_out);
        }
    }

    /* If not replaced, add it */
    if (!replaced) {
        fprintf(fp_out, "\nGRUB_CMDLINE_LINUX_DEFAULT=\"%s\"\n",
                config->cmdline_linux_default);
    }

    fclose(fp_in);
    fclose(fp_out);

    /* Replace original file */
    if (rename(temp_file, config->grub_file) != 0) {
        FG_LOG_ERROR("Failed to replace GRUB config file");
        unlink(temp_file);
        return FG_ERROR;
    }

    FG_INFO("Wrote GRUB configuration: %s", config->grub_file);

    if (safety_ctx) {
        safety_log_operation(safety_ctx, "grub_config_write", true,
                           config->grub_file);
    }

    return FG_SUCCESS;
}

/* Secure execution helper - replaces system() to prevent command injection */
static int secure_execute(const char *program, char *const argv[]) {
    pid_t pid;
    int status;

    /* Clear environment to prevent PATH manipulation */
    char *clean_env[] = {
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        NULL
    };

    pid = fork();
    if (pid < 0) {
        FG_LOG_ERROR("fork() failed: %s", strerror(errno));
        return FG_ERROR;
    }

    if (pid == 0) {
        /* Child process */
        execve(program, argv, clean_env);
        /* If execve returns, it failed */
        FG_LOG_ERROR("execve(%s) failed: %s", program, strerror(errno));
        _exit(127);
    }

    /* Parent process - wait for child */
    if (waitpid(pid, &status, 0) < 0) {
        FG_LOG_ERROR("waitpid() failed: %s", strerror(errno));
        return FG_ERROR;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        FG_LOG_ERROR("Command terminated by signal %d", WTERMSIG(status));
        return FG_ERROR;
    }

    return FG_ERROR;
}

int grub_update(safety_context_t *safety_ctx) {
    int ret;
    struct stat st;

    if (safety_ctx && safety_is_dry_run(safety_ctx)) {
        FG_INFO("[DRY-RUN] Would run GRUB update command");
        return FG_SUCCESS;
    }

    /* Determine which update command to use */
    if (stat("/usr/sbin/update-grub", &st) == 0) {
        FG_INFO("Running update-grub...");
        char *argv[] = {"/usr/sbin/update-grub", NULL};
        ret = secure_execute("/usr/sbin/update-grub", argv);
    } else if (stat("/usr/sbin/grub2-mkconfig", &st) == 0) {
        FG_INFO("Running grub2-mkconfig...");
        char *argv[] = {
            "/usr/sbin/grub2-mkconfig",
            "-o",
            "/boot/grub2/grub.cfg",
            NULL
        };
        ret = secure_execute("/usr/sbin/grub2-mkconfig", argv);
    } else {
        FG_LOG_ERROR("GRUB update command not found");
        return FG_NOT_FOUND;
    }

    if (ret != 0) {
        FG_LOG_ERROR("GRUB update failed (exit code: %d)", ret);
        return FG_ERROR;
    }

    FG_INFO("GRUB configuration updated successfully");

    if (safety_ctx) {
        safety_log_operation(safety_ctx, "grub_update", true, "GRUB updated");
    }

    return FG_SUCCESS;
}

int grub_restore_config(safety_context_t *safety_ctx) {
    /* This would restore from backup registry */
    if (!safety_ctx) {
        return FG_ERROR;
    }

    FG_INFO("GRUB config restore requires backup module integration");
    return FG_NOT_SUPPORTED; /* Placeholder */
}

bool grub_verify_config(const grub_config_t *config) {
    if (!config) {
        return false;
    }

    /* Basic validation */
    if (strlen(config->cmdline_linux_default) >= 1024) {
        FG_WARN("GRUB cmdline too long");
        return false;
    }

    /* Check for dangerous characters */
    const char *dangerous = ";&|`$\n";
    for (const char *c = dangerous; *c; c++) {
        if (strchr(config->cmdline_linux_default, *c)) {
            FG_WARN("GRUB cmdline contains dangerous character: %c", *c);
            return false;
        }
    }

    return true;
}
