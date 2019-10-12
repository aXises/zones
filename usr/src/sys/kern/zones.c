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

struct zone_entry {
	TAILQ_ENTRY(zone_entry) entry;
	zoneid_t zid;
	char *zname;
};
TAILQ_HEAD(zone_list, zone_entry);

struct zone_list zone_entries = TAILQ_HEAD_INITIALIZER(zone_entries);

struct rwlock zone_lock = RWLOCK_INITIALIZER("zone_lock");

int queue_size = 0;

struct zone_entry *
get_zone_by_name(const char *zonename) {
	struct zone_entry *zentry;
	TAILQ_FOREACH(zentry, &zone_entries, entry) {
		if (strcmp(zonename, zentry->zname) == 0) {
			return (zentry);
		}
	}
	return (NULL);
}

int
sys_zone_create(struct proc *p, void *v, register_t *retval)
{
    	printf("___________________%s!\n", __func__);
	
	struct sys_zone_create_args /* {
		syscallarg(const char *) zonename;
	} */ *uap = v;

	struct zone_entry *z_entry;
	const char *zname;
	// char zname_buf[MAXZONENAMELEN];
	int zname_len;

	zname = SCARG(uap, zonename);
	zname_len = strlen(zname);
	
	/* ENAMETOOLONG the name of the zone exceeds MAXZONENAMELEN */
	if (zname_len > MAXZONENAMELEN) {
		return (ENAMETOOLONG);
	}

	/* EPERM the current program is not in the global zone */
	/* EPERM the current user is not root */

	/* EEXIST a zone with the specified name already exists */
	if (get_zone_by_name(zname) != NULL) {
		return (EEXIST);
	}

	/* ERANGE too many zones are currently running */
	if (queue_size >= MAXZONES) {
		return (ERANGE);
	}
	/* EFAULT zonename points to a bad address */

	/* EINVAL the name of the zone contains invalid characters */

	z_entry = malloc(sizeof(struct zone_entry), M_PROC, M_WAITOK);
	z_entry->zid = queue_size;
	z_entry->zname =
	    malloc((zname_len + 1) * sizeof(char), M_PROC, M_WAITOK);
	memcpy(z_entry->zname, zname, zname_len + 1);

	printf("zone created: %s %i\n", z_entry->zname, z_entry->zid);

	rw_enter_write(&zone_lock);
	TAILQ_INSERT_TAIL(&zone_entries, z_entry, entry);
	queue_size++;
	rw_exit_write(&zone_lock);

	*retval = z_entry->zid;

	// rw_enter_read(&zone_lock);
	// struct zone_entry *e = TAILQ_FIRST(&zone_entries);

	// printf("FIRST: %i %s\n", e->zid, e->zname);
	// rw_exit_read(&zone_lock);
	
	// rw_enter_read(&zone_lock);
	// struct zone_entry *e2 = TAILQ_NEXT(e, entry);
	// printf("works!!\n");
	// printf("LAST: %i %s\n", e2->zid, e2->zname);
	// rw_exit_read(&zone_lock);

	// struct zone_entry *e;
	// TAILQ_FOREACH(e, &zone_entries, entry) {
	// 	// if (i >= 5) {
	// 	// 	printf("reached 5\n");
	// 	// 	return 0;
	// 	// }
	// 	printf("q: %i %s\n", e->zid, e->zname);
	// }

    	return (0);
}

int
sys_zone_destroy(struct proc *p, void *v, register_t *retval)
{
    	printf("___________________%s!\n", __func__);
    	return (0);
}

int
sys_zone_enter(struct proc *p, void *v, register_t *retval)
{
    	printf("___________________%s!\n", __func__);
    	return (0);
}

int
sys_zone_list(struct proc *p, void *v, register_t *retval)
{
    	printf("___________________%s!\n", __func__);
    	return (0);
}

int
sys_zone_name(struct proc *p, void *v, register_t *retval)
{
    	printf("___________________%s!\n", __func__);
    	return (0);
}

int
sys_zone_lookup(struct proc *p, void *v, register_t *retval)
{
    	printf("___________________%s!\n", __func__);
    	return (0);
}
