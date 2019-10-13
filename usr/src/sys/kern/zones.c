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
get_zone_by_name(const char *zonename)
{
	struct zone_entry *zentry;

	rw_enter_read(&zone_lock);
	TAILQ_FOREACH(zentry, &zone_entries, entry) {
		if (strcmp(zonename, zentry->zname) == 0) {
			rw_exit_read(&zone_lock);
			return (zentry);
		}
	}
	rw_exit_read(&zone_lock);
	return (NULL);
}

struct zone_entry *
get_zone_by_id(zoneid_t id)
{
	struct zone_entry *zentry;

	rw_enter_read(&zone_lock);
	TAILQ_FOREACH(zentry, &zone_entries, entry) {
		if (zentry->zid == id) {
			rw_exit_read(&zone_lock);
			return (zentry);
		}
	}
	rw_exit_read(&zone_lock);
	return (NULL);
}

zoneid_t
get_next_available_id(void)
{
	struct zone_entry *zentry;
	int temp, n;
	int *ids;

	// printf("queue-----\n");
	// TAILQ_FOREACH(zentry, &zone_entries, entry) {
	// 	printf("elem: %s %i\n", zentry->zname, zentry->zid);
	// }
	// printf("queue-----\n");

	ids = malloc(sizeof(int) * queue_size, M_PROC, M_WAITOK);

	n = 0;
	rw_enter_read(&zone_lock);
	TAILQ_FOREACH(zentry, &zone_entries, entry) {
		ids[n] = zentry->zid;
		n++;
	}
	rw_exit_read(&zone_lock);

	for (int i = 0; i < n; i++) {
		for (int j = 0; j < n; j++) {
			if (ids[i] < ids[j]) {
				temp = ids[i];
				ids[i] = ids[j];
				ids[j] = temp;
			}
		}
	}

	// for (int i = 0; i < n; i++) {
	// 	printf("sorted ids: %i\n", ids[i]);
	// }

	for (int i = 1; i < n; i++) {
		if (ids[i] - ids[i - 1] != 1) {
			// printf("available id (gap) %i\n", i + 1);
			return (i + 1);
		}
	}
	// printf("available id %i\n", n + 1);
	return (n + 1);

	// index = 1;
	// TAILQ_FOREACH(zentry, &zone_entries, entry) {
	// 	if (zentry->zid != ids[index - 1]) {
	// 		printf("a NEXT AVAILABLE ID AT %i\n", index);
	// 		return (index);
	// 	}
	// 	index++;
	// }
	// printf("b NEXT AVAILABLE ID AT %i\n", index);
	// return index - 1;
}

int
sys_zone_create(struct proc *p, void *v, register_t *retval)
{
    	printf("___________________%s!\n", __func__);
	
	struct sys_zone_create_args /* {
		syscallarg(const char *) zonename;
	} */ *uap = v;

	struct zone_entry *zentry;
	const char *zname;
	// char zname_buf[MAXZONENAMELEN];
	int zname_len;
	size_t done;

	*retval = -1;
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

	zentry = malloc(sizeof(struct zone_entry), M_PROC, M_WAITOK);
	zentry->zid = get_next_available_id();
	zentry->zname =
	    malloc((zname_len + 1) * sizeof(char), M_PROC, M_WAITOK);
	copyinstr(zname, zentry->zname, zname_len + 1, &done);

	printf("zone created: %s %i\n", zentry->zname, zentry->zid);

	rw_enter_write(&zone_lock);
	TAILQ_INSERT_TAIL(&zone_entries, zentry, entry);
	queue_size++;
	rw_exit_write(&zone_lock);

	*retval = zentry->zid;

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
