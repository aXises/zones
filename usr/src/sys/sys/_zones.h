struct zone_entry {
	TAILQ_ENTRY(zone_entry) entry;
	zoneid_t zid;
	char zname[MAXZONENAMELEN];
};

struct zone_entry *get_zone_by_id(zoneid_t);
