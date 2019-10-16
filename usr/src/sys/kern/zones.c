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
#include <sys/sysctl.h>

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

int queue_size = 1;

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

	for (int i = 1; i < n; i++) {
		if (ids[i] - ids[i - 1] != 1) {
			return (i + 1);
		}
	}
	return (n + 1);
}

int
in_global_zone(struct proc *p)
{
	return (p->p_p->zone_id == 0);
}

int
is_root_user(struct proc *p)
{
        return (suser(p) == 0);
}

int
sys_zone_create(struct proc *p, void *v, register_t *retval)
{
    	printf("%s!\n", __func__);
	
	struct sys_zone_create_args /* {
		syscallarg(const char *) zonename;
	} */ *uap = v;

	struct zone_entry *zentry;
	const char *zname;
	int zname_len;

	zname = SCARG(uap, zonename);
	zname_len = strlen(zname);
	
	/* ENAMETOOLONG the name of the zone exceeds MAXZONENAMELEN */
	if (zname_len > MAXZONENAMELEN) {
		return (ENAMETOOLONG);
	}

	/* EPERM the current program is not in the global zone */
	/* EPERM the current user is not root */
	if (!in_global_zone(p) || !is_root_user(p)) {
		return (EPERM); 
	}

	/* EEXIST a zone with the specified name already exists */
	if (get_zone_by_name(zname) != NULL) {
		return (EEXIST);
	}

	/* ERANGE too many zones are currently running */
	if (queue_size >= MAXZONES) {
		return (ERANGE);
	}

	/* EINVAL the name of the zone contains invalid characters */

	zentry = malloc(sizeof(struct zone_entry), M_PROC, M_WAITOK);
	zentry->zid = get_next_available_id();
	zentry->zname =
	    malloc((zname_len + 1) * sizeof(char), M_PROC, M_WAITOK);
	
	if (copyinstr(zname, zentry->zname, zname_len + 1, NULL)) {
		free(zentry->zname, M_PROC, M_WAITOK);
		free(zentry, M_PROC, M_WAITOK);
		return (EFAULT);
	}


	printf("zone created: %s %i\n", zentry->zname, zentry->zid);

	rw_enter_write(&zone_lock);
	TAILQ_INSERT_TAIL(&zone_entries, zentry, entry);
	queue_size++;
	rw_exit_write(&zone_lock);

	*retval = zentry->zid;

    	return (0);
}

int
sys_zone_destroy(struct proc *p, void *v, register_t *retval)
{
    	printf("%s!\n", __func__);

	struct sys_zone_destroy_args /* {
		syscallarg(zoneid_t) z;
	} */ *uap = v;

	struct zone_entry *zentry;
	*retval = -1;

	/* EPERM the current program is not in the global zone */
	/* EPERM the current user is not root */
	if (!in_global_zone(p) || !is_root_user(p)) {
		return (EPERM); 
	}

	/* ESRCH the specified zone does not exist */
	if ((zentry = get_zone_by_id(SCARG(uap, z))) == NULL) {
		return (ESRCH);
	}
	/* EBUSY the specified zone is still in use, */
	/* ie, a process is still running in the zone */

	printf("zone destroyed: %s %i\n", zentry->zname, zentry->zid);

	rw_enter_write(&zone_lock);
	free(zentry->zname, M_PROC, M_WAITOK);
	TAILQ_REMOVE(&zone_entries, zentry, entry);
	queue_size--;
	rw_exit_write(&zone_lock);

	*retval = 0;
    	return (0);
}

int
sys_zone_enter(struct proc *p, void *v, register_t *retval)
{
    	printf("%s!\n", __func__);

	struct sys_zone_destroy_args /* {
		syscallarg(zoneid_t) z;
	} */ *uap = v;

	struct zone_entry *zentry;

	// TODO allow entering global zone.

	/* EPERM the current program is not in the global zone */
	/* EPERM the current user is not root */
	if (!in_global_zone(p) || !is_root_user(p)) {
		return (EPERM); 
	}

	/* ESRCH the specified zone does not exist */
	if ((zentry = get_zone_by_id(SCARG(uap, z))) == NULL) {
		return (ESRCH);
	}

	p->p_p->zone_id = zentry->zid;

    	return (0);
}

int
sys_zone_list(struct proc *p, void *v, register_t *retval)
{
    	printf("%s!\n", __func__);

	struct sys_zone_list_args /* {
		syscallarg(zoneid_t *) zs;
		syscallarg(size_t *) nzs;
	} */ *uap = v;

	struct zone_entry *zentry;
	zoneid_t *ids, zs_in;
	size_t nzs_in, n;

	/* EFAULT zs or nzs point to a bad address */
	if (copyin(SCARG(uap, zs), &zs_in, sizeof(zoneid_t *)) ||
	    copyin(SCARG(uap, nzs), &nzs_in, sizeof(size_t *))) {
		return (EFAULT);
	}
	printf("nzs: %zu\n", nzs_in);
	n = 0;
	if (in_global_zone(p)) {
		printf("in global zone\n");
		ids = malloc(sizeof(zoneid_t) * (queue_size + 1),
		    M_TEMP, M_WAITOK);
		ids[0] = 0;
		n++;
		rw_enter_read(&zone_lock);
		TAILQ_FOREACH(zentry, &zone_entries, entry) {
			ids[n] = zentry->zid;
			n++;
		}
		rw_exit_read(&zone_lock);
	} else {
		printf("in zone %i\n", p->p_p->zone_id);
		ids = malloc(sizeof(zoneid_t), M_TEMP, M_WAITOK);
		if ((zentry = get_zone_by_id(p->p_p->zone_id)) == NULL) {
			printf("zone not found?\n");
		}
		ids[0] = zentry->zid;
		n++;
	}

	/* ERANGE if the number at nzs is less than the number of running */
	/* zones in the system */
	printf("%zu %zu\n", nzs_in, n);
	if (nzs_in < n) {
		free(ids, M_TEMP, M_WAITOK);
		return (ERANGE);
	}
	
	if (copyout(ids, SCARG(uap, zs), sizeof(zoneid_t) * n)) {
		free(ids, M_TEMP, M_WAITOK);
		return (EFAULT);
	}
	
	free(ids, M_TEMP, M_WAITOK);
    	
	if (copyout(&n, SCARG(uap, nzs), sizeof(size_t *))) {
		return (EFAULT);
	}

	return (0);
}

int
sys_zone_name(struct proc *p, void *v, register_t *retval)
{
    	printf("%s!\n", __func__);

	struct sys_zone_name_args /* {
		syscallarg(zoneid_t) z;
		syscallarg(char *) name;
		syscallarg(size_t) namelen;
	} */ *uap = v;
	struct zone_entry *zentry;
	zoneid_t zid;

	zid = SCARG(uap, z);

	if (zid == 0) {
		char g[MAXZONENAMELEN] = "global";
		if (copyoutstr(g, SCARG(uap, name), SCARG(uap, namelen), NULL)) {
			return (EFAULT);
		}
		return (0);
	}

	if (zid == -1) {
		zentry = get_zone_by_id(p->p_p->zone_id);
	} else {
		zentry = get_zone_by_id(zid);
	}

	/* ESRCH The specified zone does not exist */
	if (zentry == NULL) {
		return (ESRCH);
	}
	/* ESRCH The specified zone is not visible in a non-global zone */
	/* EFAULT name refers to a bad memory address */
	/* ENAMETOOLONG The requested name is longer than namelen bytes. */
	copyoutstr(zentry->zname, SCARG(uap, name), SCARG(uap, namelen), NULL);
    	return (0);
}

int
sys_zone_lookup(struct proc *p, void *v, register_t *retval)
{
    	printf("%s!\n", __func__);

	struct sys_zone_lookup_args /* {
		syscallarg(char *) name;
	} */ *uap = v;
	struct zone_entry *zentry;
	const char *zname;
	int zname_len;
	
	zname = SCARG(uap, name);
	zname_len = strlen(zname);

	if (zname == NULL) {
		*retval = p->p_p->ps_pid;
		return (0);
	}

	/* ESRCH The specified zone does not exist */
	if ((zentry = get_zone_by_name(zname)) == NULL) {
		return (ESRCH);
	}

	/* ESRCH The specified zone is not visible in a non-global zone */

	/* EFAULT name refers to a bad memory address */

	/* ENAMETOOLONG the name of the zone exceeds MAXZONENAMELEN */
	if (zname_len > MAXZONENAMELEN) {
		return (ENAMETOOLONG);
	}

	*retval = zentry->zid;

    	return (0);
}
