#!/usr/bin/env - /bin/bash
# $Id: T-002.sh,v 1.1.2.1 2004/05/28 08:35:01 lars Exp $

Start RS_1 Node_1

sleep 10

Fail_Disk Disk_1
Node_State Node_1

sleep 5

Stop RS_1 
Node_State Node_1

Start RS_1 Node_2 # Oops. Node_1 panics ??

