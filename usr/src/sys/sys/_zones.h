struct zone_entry {
	TAILQ_ENTRY(zone_entry) entry;
	zoneid_t zid;
	char zname[MAXZONENAMELEN];
        char hostname[MAXHOSTNAMELEN];
        char domainname[MAXHOSTNAMELEN];
        long hostid;
        struct timeval *boottime;
};

struct zone_entry *get_zone_by_id(zoneid_t);
