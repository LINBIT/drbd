#!/usr/bin/env - /bin/bash
# $Id: T-001.sh,v 1.1.2.1 2004/05/28 08:35:01 lars Exp $

echo "START"
Start RS_1 Node_1
Start RS_2 Node_2

sleep 30

echo "MOVE"
Relocate RS_1 Node_2
Relocate RS_2 Node_1

sleep 30

echo "STOP"
Stop RS_1
Stop RS_2

echo "PASSED"
