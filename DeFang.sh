#!/bin/bash 
# URL DeFang Script for those pesky malvvares links

MALVAR="$1" # Parameter
{ echo $MALVAR | perl -pe 's/h(tt)p/hxxp/g and s/\./[.]/g' | pbcopy ; echo " "; echo $MALVAR | perl -pe 's/h(tt)p/hxxp/g and s/\./[.]/g' ; echo " "; } 
# Defang command string
