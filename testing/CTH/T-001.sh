#!/usr/bin/env - /bin/bash

: ${RS_1:?no RS_1 defined...}
: ${RS_2:?no RS_2 defined...}

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
