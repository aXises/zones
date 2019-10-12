#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/tree.h>
#include <sys/rwlock.h>
#include <sys/mount.h>
#include <sys/atomic.h>
#include <sys/syscallargs.h>

#include <sys/_zones.h>
#include <sys/zones.h>

int
sys_zone_create(struct proc *p, void *v, register_t *retval)
{
    printf("%s!\n", __func__);
    return (0);
}

int
sys_zone_destroy(struct proc *p, void *v, register_t *retval)
{
    printf("%s!\n", __func__);
    return (0);
}

int
sys_zone_enter(struct proc *p, void *v, register_t *retval)
{
    printf("%s!\n", __func__);
    return (0);
}

int
sys_zone_list(struct proc *p, void *v, register_t *retval)
{
    printf("%s!\n", __func__);
    return (0);
}

int
sys_zone_name(struct proc *p, void *v, register_t *retval)
{
    printf("%s!\n", __func__);
    return (0);
}

int
sys_zone_lookup(struct proc *p, void *v, register_t *retval)
{
    printf("%s!\n", __func__);
    return (0);
}
