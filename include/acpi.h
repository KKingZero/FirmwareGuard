#ifndef ACPI_H
#define ACPI_H

#include <stdint.h>

// ACPI table parsing
int parse_acpi_tables(void);
char *get_acpi_table_info(const char *table_name);

#endif // ACPI_H