/* 
   PAKET( name,
          TYPE ( pn, member )
          ...
   )

   You may never reissue one of the pn arguments
*/

PACKET(syncer_conf,
       INTEGER(1,rate)
       INTEGER(2,after)
       INTEGER(3,al_extents)
)

PACKET(net_conf,
       STRING(4,my_addr,128)
       INTEGER(5,timeout)
)

#undef PACKET
#undef STRING
#undef INTEGER
