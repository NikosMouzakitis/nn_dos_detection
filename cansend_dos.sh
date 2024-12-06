#!/bin/bash

# Check if NORMAL_IDS.txt exists
if [ ! -f NORMAL_IDS.txt ]; then
  echo "NORMAL_IDS.txt not found!"
  exit 1
fi

# Load CAN IDs from the file
can_ids=$(cat NORMAL_IDS.txt)
counter=0
# Loop to send traffic
for can_id in $can_ids; do

  if [ $counter -ge 30000 ]; then
	  break
  fi
  
  # Remove the first character of the can_id
  can_id="${can_id:1}"
  ((counter++))
  # Generate random data for each CAN ID (up to 8 bytes)
  data=$(xxd -p -l 8 /dev/urandom)
  
  # Format the data as required by cansend
  # This sends the frame in the expected format: <can_id>#<data>
  cansend vcan0 "000#$data"

  # Sleep for a short interval to control the frequency of messages
 # sleep 0.1
done

