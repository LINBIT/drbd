#!/usr/bin/env - /bin/bash
# $Id: T-001.sh,v 1.1.2.3 2004/06/01 09:36:55 lars Exp $

echo "START"
Start RS_1 Node_1
Start RS_2 Node_2

sleep 30

echo "MOVE"
Reloc RS_1 Node_2
Reloc RS_2 Node_1

sleep 30

echo "STOP"
Stop RS_1
Stop RS_2
