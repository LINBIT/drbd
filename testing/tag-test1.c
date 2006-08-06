#include "tag-magic.h"

int main(int argc, char** argv)
{
	struct syncer_conf sc = (struct syncer_conf) { 250, -1, 247 };
	struct syncer_conf sc2;

	struct net_conf nc = (struct net_conf) { "hallo welt",60 };
	struct net_conf nc2;

	char sct[syncer_conf_tag_size];
	char nct[net_conf_tag_size];

	dump_syncer_conf("sc",&sc);
	dump_net_conf("nc",&nc);

	printf("Converting to tag list\n");
	syncer_conf_to_tags(&sc,sct);
	net_conf_to_tags(&nc,nct);

	dump_tag_list("sct",sct);
	dump_tag_list("nct",nct);

	printf("Converting from tag list\n");
	syncer_conf_from_tags(sct,&sc2);
	net_conf_from_tags(nct,&nc2);

	dump_syncer_conf("sc2",&sc2);
	dump_net_conf("nc2",&nc2);

}
