#include <stdio.h>
#include <zones.h>

int
main(int argc, char *argv[])
{
	char zonename[MAXZONENAMELEN];
	zoneid_t zid;
	size_t nzs = 1;
	printf("MAXZONES: %u, MAXZONEIDS: %u\n", MAXZONES, MAXZONEIDS);
	zone_create("test");
	zone_destroy(0);
	zone_enter(0);
	zone_list(&zid, &nzs);
	zone_name(0, zonename, sizeof(zonename));
	return (0);
}