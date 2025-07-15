#!/bin/bash

#set -e

read -p "Input IP Address : " inputIP
read -p "Input VT Api Key : " apiKey
curl -s -X GET https://www.virustotal.com/api/v3/search?query=$inputIP -H 'Content-Type: application/json' -H "x-apikey: $apiKey" | jq . > $inputIP-VT.json

fileNameVT="$inputIP-VT.json"
ipaddrID=$(jq -r '.data[]["id"]' $fileNameVT)
asOwner=$(jq -r '.data[]["attributes"]["as_owner"]' $fileNameVT)
asN=$(jq -r '.data[]["attributes"]["asn"]' $fileNameVT)
country=$(jq -r '.data[]["attributes"]["country"]' $fileNameVT)
network=$(jq -r '.data[]["attributes"]["network"]' $fileNameVT)
regionIntReg=$(jq -r '.data[]["attributes"]["regional_internet_registry"]' $fileNameVT)
lastAnalysisStatsMal=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["malicious"]' $fileNameVT)
lastAnalysisStatsSus=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["suspicious"]' $fileNameVT)
lastAnalysisStatsUnd=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["undetected"]' $fileNameVT)
lastAnalysisStatsHar=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["harmless"]' $fileNameVT)
lastAnalysisStatsTim=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["timeout"]' $fileNameVT)


echo "=========VIRUS TOTAL============="
echo "=====VIRUS TOTAL IP OUTPUT====="
echo "IP Address : $ipaddrID"
echo "AS Owner : $asOwner"
echo "ASN : $asN"
echo "================================="
echo "=====LAST ANALYSIS STATS========="
echo "================================="
echo "Malicious : $lastAnalysisStatsMal"
echo "Suspicious : $lastAnalysisStatsSus"
echo "Undetected : $lastAnalysisStatsUnd"
echo "Harmless : $lastAnalysisStatsHar"
echo "Timeout : $lastAnalysisStatsTim"