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

#include <sys/zones.h>

TAILQ_HEAD(zone_list, zone_entry);

struct zone_list zone_entries = TAILQ_HEAD_INITIALIZER(zone_entries);

struct rwlock zone_lock = RWLOCK_INITIALIZER("zone_lock");

size_t queue_size = 1;

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
	int temp, n, i, j;
	int *ids;

	if (queue_size < 2) {
		return (1);
	}

	ids = malloc(sizeof(int) * queue_size, M_TEMP, M_WAITOK);

	n = 1;
	ids[0] = 0;
	rw_enter_read(&zone_lock);
	TAILQ_FOREACH(zentry, &zone_entries, entry) {
		ids[n] = zentry->zid;
		n++;
	}
	rw_exit_read(&zone_lock);

	for (i = 0; i < n; i++) {
		for (j = 0; j < n; j++) {
			if (ids[i] < ids[j]) {
				temp = ids[i];
				ids[i] = ids[j];
				ids[j] = temp;
			}
		}
	}

	for (i = 1; i < n; i++) {
		if (ids[i] - ids[i - 1] != 1) {
			free(ids, M_TEMP, sizeof(int) * (queue_size));
			return (i);
		}
	}
	free(ids, M_TEMP, sizeof(int) * (queue_size));
	return (n);
}

int
is_digit(char c)
{
	return ((c >= 48) && (c <= 57));
}

int
is_alpha(char c)
{
	return (((c >= 65) && (c <= 90)) || ((c >= 97) && (c <= 122)));
}

int
is_valid_name(const char *name)
{
	for (int i = 0; i < strlen(name); i++) {
		if (name[i] == '-' || name[i] == '_') {
			continue;
		}
		if (!is_alpha(name[i]) && !is_digit(name[i])) {
			return (0);
		}
	}
	return (1);
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
	struct sys_zone_create_args /* {
		syscallarg(const char *) zonename;
	} */ *uap = v;

	struct zone_entry *zentry;
	const char *zname;
	char zname_in[MAXZONENAMELEN];
	size_t zname_len;
	int error;

	*retval = -1;
	zname = SCARG(uap, zonename);

	/* EFAULT zonename points to a bad address */
	/* ENAMETOOLONG the name of the zone exceeds MAXZONENAMELEN */
	if ((error = copyinstr(zname, zname_in, MAXZONENAMELEN, &zname_len))) {
		return (error);
	}

	/* EINVAL the name of the zone contains invalid characters */
	if (!is_valid_name(zname)) {
		return (EINVAL);
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

	zentry = malloc(sizeof(struct zone_entry), M_PROC, M_WAITOK);
	zentry->zid = get_next_available_id();
	zentry->domainname[0] = '\0';
	zentry->hostid = 0;
	zentry->boottime = malloc(sizeof(struct timeval), M_PROC, M_WAITOK);
	microtime(zentry->boottime);

	if (copyinstr(zname, zentry->zname, zname_len, NULL)
	    || copyinstr(zname, zentry->hostname, zname_len, NULL)) {
		free(zentry, M_PROC, sizeof(struct zone_entry));
		return (EFAULT);
	}

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
	struct sys_zone_destroy_args /* {
		syscallarg(zoneid_t) z;
	} */ *uap = v;

	struct zone_entry *zentry;
	struct process *pr;
	zoneid_t zid, p_zid;
	*retval = -1;

	zid = SCARG(uap, z);

	/* EPERM the current program is not in the global zone */
	/* EPERM the current user is not root */
	if (!in_global_zone(p) || !is_root_user(p)) {
		return (EPERM);
	}

	/* ESRCH the specified zone does not exist */
	if ((zentry = get_zone_by_id(zid)) == NULL) {
		return (ESRCH);
	}

	/* EBUSY the specified zone is still in use, */
	/* ie, a process is still running in the zone */
	LIST_FOREACH(pr, &allprocess, ps_list) {
		p_zid = pr->zone_id;
		if (p_zid != 0) {
			if (p_zid == zentry->zid) {
				return (EBUSY);
			}
		}
	}

	rw_enter_write(&zone_lock);
	TAILQ_REMOVE(&zone_entries, zentry, entry);
	queue_size--;
	rw_exit_write(&zone_lock);

	free(zentry, M_PROC, sizeof(struct zone_entry));

	*retval = 0;

	return (0);
}

int
sys_zone_enter(struct proc *p, void *v, register_t *retval)
{
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

	p->p_p->zone_id = zentry->zid;

	*retval = 0;

	return (0);
}

int
sys_zone_list(struct proc *p, void *v, register_t *retval)
{
	struct sys_zone_list_args /* {
		syscallarg(zoneid_t *) zs;
		syscallarg(size_t *) nzs;
	} */ *uap = v;

	struct zone_entry *zentry;
	zoneid_t *ids, zs_in;
	size_t nzs_in, n;
	*retval = -1;

	/* EFAULT zs or nzs point to a bad address */
	if (copyin(SCARG(uap, zs), &zs_in, sizeof(zoneid_t *)) ||
		copyin(SCARG(uap, nzs), &nzs_in, sizeof(size_t *))) {
		return (EFAULT);
	}

	n = 0;
	if (in_global_zone(p)) {
		ids = malloc(sizeof(zoneid_t) * (queue_size),
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
		ids = malloc(sizeof(zoneid_t), M_TEMP, M_WAITOK);
		ids[0] = p->p_p->zone_id;
		n++;
	}

	/* ERANGE if the number at nzs is less than the number of running */
	/* zones in the system */
	if (nzs_in < n) {
		free(ids, M_TEMP, sizeof(zoneid_t) * n);
		return (ERANGE);
	}

	if (copyout(ids, SCARG(uap, zs), sizeof(zoneid_t) * n)) {
		free(ids, M_TEMP, sizeof(zoneid_t) * n);
		return (EFAULT);
	}

	free(ids, M_TEMP, sizeof(zoneid_t) * n);

	if (copyout(&n, SCARG(uap, nzs), sizeof(size_t *))) {
		return (EFAULT);
	}

	*retval = 0;
	return (0);
}

int
sys_zone_name(struct proc *p, void *v, register_t *retval)
{
	struct sys_zone_name_args /* {
		syscallarg(zoneid_t) z;
		syscallarg(char *) name;
		syscallarg(size_t) namelen;
	} */ *uap = v;
	struct zone_entry *zentry;
	char *zname_in;
	char zname[MAXZONENAMELEN];
	zoneid_t zid;
	size_t zname_len;
	const char global_zname[MAXZONENAMELEN] = "global";
	*retval = -1;

	zid = SCARG(uap, z);
	zname_in = SCARG(uap, name);
	zname_len = SCARG(uap, namelen);

	/* EFAULT name refers to a bad memory address */
	if (zname_in == NULL) {
		return (EFAULT);
	}

	if (copyinstr(zname_in, zname, zname_len, NULL)) {
		return (EFAULT);
	}

	/* ENAMETOOLONG The requested name is longer than namelen bytes. */
	if (zname_len > MAXZONENAMELEN) {
		return (ENAMETOOLONG);
	}

	if (zid == -1) {
		if (in_global_zone(p)) {
			if (copyoutstr(global_zname, zname_in, zname_len, NULL)) {
				return (EFAULT);
			}
			*retval = 0;
			return (0);
		}
		zentry = get_zone_by_id(p->p_p->zone_id);
	} else {
		zentry = get_zone_by_id(zid);
	}

	if (in_global_zone(p) && zid == 0) {
		if (copyoutstr(global_zname, zname_in, zname_len, NULL)) {
			return (EFAULT);
		}
		*retval = 0;
		return (0);
	}

	/* ESRCH The specified zone does not exist */
	if (zentry == NULL) {
		return (ESRCH);
	}

	if (copyoutstr(zentry->zname, zname_in, zname_len, NULL)) {
		return (EFAULT);
	}

	*retval = 0;
	return (0);
}

int
sys_zone_lookup(struct proc *p, void *v, register_t *retval)
{
	struct sys_zone_lookup_args /* {
		syscallarg(char *) name;
	} */ *uap = v;

	struct zone_entry *zentry;
	const char *zname_in;
	char zname[MAXZONENAMELEN];
	size_t zname_len;
	int error;
	*retval = -1;

	zname_in = SCARG(uap, name);

	/* Zone ID returned if name is NULL */
	if (zname_in == NULL) {
		*retval = p->p_p->zone_id;
		return (0);
	}

	/* EFAULT name refers to a bad memory address */
	/* ENAMETOOLONG the name of the zone exceeds MAXZONENAMELEN */
	if ((error = copyinstr(zname_in, zname, MAXZONENAMELEN, &zname_len))) {
		return (error);
	}

	if (strcmp(zname, "global") == 0 && in_global_zone(p)) {
		*retval = 0;
		return (0);
	}

	/* ESRCH The specified zone does not exist */
	if ((zentry = get_zone_by_name(zname)) == NULL) {
		return (ESRCH);
	}

	/* ESRCH The specified zone is not visible in a non-global zone */
	if (!in_global_zone(p) && p->p_p->zone_id != zentry->zid) {
		return (ESRCH);
	}

	*retval = zentry->zid;

	return (0);
}
