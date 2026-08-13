#!/bin/bash
export IP_ADDR=$(awk 'END{print $1}' /etc/hosts)

cp /mnt/ueransim/${COMPONENT_NAME}.yaml /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|MNC|'$MNC'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|MCC|'$MCC'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|UE_KI|'$UE2_KI'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|UE_OPC|'$UE2_OPC'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|UE_AMF|'$UE2_AMF'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|UE_IMEISV|'$UE2_IMEISV'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|UE_IMEI|'$UE2_IMEI'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|UE_IMSI|'$UE2_IMSI'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml
sed -i 's|NR_GNB_IP|'$NR_GNB_IP'|g' /UERANSIM/config/${COMPONENT_NAME}.yaml

./nr-ue -c ../config/${COMPONENT_NAME}.yaml &
exec bash $@
