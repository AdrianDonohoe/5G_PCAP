#!/bin/bash
export IP_ADDR=$(awk 'END{print $1}' /etc/hosts)

cp /mnt/ueransim/${COMPONENT_NAME}.yaml /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|MNC|'$MNC'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|MCC|'$MCC'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|UE_KI|'$UE3_KI'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|UE_OPC|'$UE3_OPC'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|UE_AMF|'$UE3_AMF'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|UE_IMEISV|'$UE3_IMEISV'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|UE_IMEI|'$UE3_IMEI'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|UE_IMSI|'$UE3_IMSI'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|NR_GNB_IP|'$NR_GNB_IP'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml

./nr-ue -c ../config/${COMPONENT_NAME}.yaml &
exec bash $@
