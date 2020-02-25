#ifndef FDTOOLS_H
#define FDTOOS_H

#include <dirent.h>
#include <errno.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "steque.h"


void scan_fd(DIR * dir, steque_t * queue, int target_pid);




#endif