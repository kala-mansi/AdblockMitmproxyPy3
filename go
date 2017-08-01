#!/bin/bash

PORT=8118
mitmdump -s adblock.py -p $PORT --ignore ^.*?:443$

