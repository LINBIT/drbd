/* 
   PAKET( name,
          TYPE ( pn, pr, member )
          ...
   )

   You may never reissue one of the pn arguments
*/

#if !defined(PACKET) || !defined(STRING) || !defined(INTEGER) || !defined(BIT) || !defined(INT64)
#error "The macros PACKET, STRING, INTEGER, INT64 and BIT needs to be defined"
#endif

PACKET(primary,
       BIT(		1,	T_MAY_IGNORE,	overwrite_peer)
)

PACKET(secondary, )

PACKET(disk_conf,
	INT64(  	2,	T_MAY_IGNORE,	disk_size)
	STRING(		3,	T_MANDATORY,	backing_dev,	32)
	STRING(		4,	T_MANDATORY,	meta_dev,	32)
	INTEGER(	5,	T_MANDATORY,	meta_dev_idx)
	INTEGER(	6,	T_MAY_IGNORE,	on_io_error)
	INTEGER(	7,	T_MAY_IGNORE,	fencing)
)

PACKET(detach, )

PACKET(net_conf,
	STRING(		8,	T_MANDATORY,	my_addr,	128)
	STRING(		9,	T_MANDATORY,	peer_addr,	128)
	STRING(		10,	T_MAY_IGNORE,	shared_secret,	SHARED_SECRET_MAX)
	STRING(		11,	T_MAY_IGNORE,	cram_hmac_alg,	SHARED_SECRET_MAX)
	INTEGER(	14,	T_MAY_IGNORE,	timeout)
	INTEGER(	15,	T_MANDATORY,	wire_protocol)
	INTEGER(	16,	T_MAY_IGNORE,	try_connect_int)
	INTEGER(	17,	T_MAY_IGNORE,	ping_int)
	INTEGER(	18,	T_MAY_IGNORE,	max_epoch_size)
	INTEGER(	19,	T_MAY_IGNORE,	max_buffers)
	INTEGER(	20,	T_MAY_IGNORE,	unplug_watermark)
	INTEGER(	21,	T_MAY_IGNORE,	sndbuf_size)
	INTEGER(	22,	T_MAY_IGNORE,	ko_count)
	INTEGER(	24,	T_MAY_IGNORE,	after_sb_0p)
	INTEGER(	25,	T_MAY_IGNORE,	after_sb_1p)
	INTEGER(	26,	T_MAY_IGNORE,	after_sb_2p)
	BIT(		27,	T_MAY_IGNORE,	want_lose)
	BIT(		28,	T_MAY_IGNORE,	two_primaries)
)

PACKET(disconnect, )

PACKET(resize,
	INT64(  	29,	T_MAY_IGNORE,	resize_size)
)

PACKET(syncer_conf,
	INTEGER(	30,	T_MAY_IGNORE,	rate)
	INTEGER(  	31,	T_MAY_IGNORE,	after)
	INTEGER(  	32,	T_MAY_IGNORE,	al_extents)
)

PACKET(invalidate, )
PACKET(invalidate_peer, )
PACKET(pause_sync, )
PACKET(resume_sync, )
PACKET(suspend_io, )
PACKET(resume_io, )
PACKET(outdate, )
PACKET(get_config, )
PACKET(get_state,
	INTEGER(	33,	T_MAY_IGNORE,	state_i)
)

PACKET(get_uuids,
	STRING(		34,	T_MAY_IGNORE,	uuids,	(UUID_SIZE*sizeof(__u64)))
	INTEGER(  	35,	T_MAY_IGNORE,	uuids_flags)
)

PACKET(get_timeout_flag,
	BIT(		36,	T_MAY_IGNORE,	use_degraded)
)

#undef PACKET
#undef INTEGER
#undef INT64
#undef BIT
#undef STRING

