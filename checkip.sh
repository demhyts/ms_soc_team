#!/bin/bash

#set -e

#Clean up previous output files
rm -f *.json
read -p "Input IP Address : " inputIP
abuseIPDBApiKey="c86fa6fb4ad10387d20164181035e8be6d50ba8be72d76e91847beabfe0f7bbaf3467429236e97c8"
VTapiKey="5e92bfe394fe33287012dced2c1937dbdbf1b6ec2825a1eadd6f60f5180a593d"
curl -s -X GET https://www.virustotal.com/api/v3/search?query=$inputIP -H 'Content-Type: application/json' -H "x-apikey: $VTapiKey" | jq . > $inputIP-VT.json
curl -s -G https://api.abuseipdb.com/api/v2/check   --data-urlencode "ipAddress=$inputIP"  -d maxAgeInDays=90 -d verbose -H "Key: $abuseIPDBApiKey"   -H "Accept: application/json" | jq . > $inputIP-Abuse.json


#VirusTotal API Response Parsing
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

#AbuseIPDB API Response Parsing
fileNameAbuse="$inputIP-Abuse.json"
abuseIPAddr=$(jq -r '.data["ipAddress"]' $fileNameAbuse)
abuseisWhite=$(jq -r '.data["isWhitelisted"]' $fileNameAbuse)
abuseConfScore=$(jq -r '.data["abuseConfidenceScore"]' $fileNameAbuse)
abuseCountryName=$(jq -r '.data["countryName"]' $fileNameAbuse)
abuseUsageType=$(jq -r '.data["usageType"]' $fileNameAbuse)
abuseISP=$(jq -r '.data["isp"]' $fileNameAbuse)
abuseDomain=$(jq -r '.data["domain"]' $fileNameAbuse)
abuseTotalReports=$(jq -r '.data["totalReports"]' $fileNameAbuse)
abuseLastReportedAt=$(jq -r '.data["lastReportedAt"]' $fileNameAbuse)
#Print Results API Query
echo "=========VIRUS TOTAL============="
echo "=====VIRUS TOTAL IP OUTPUT======="
echo "IP Address : $ipaddrID"
echo "AS Owner : $asOwner"
echo "ASN : $asN"
echo "================================="
echo "=====LAST ANALYSIS STATS========="
echo "================================="
echo "Malicious : $lastAnalysisStatsMal"
echo "Suspicious : $lastAnalysisStatsSus"
echo "Timeout : $lastAnalysisStatsTim"
echo "Harmless : $lastAnalysisStatsHar"
echo "Undetected : $lastAnalysisStatsUnd"
echo "================================="
echo "=========ABUSEIPDB==============="
echo "=====ABUSEIPDB OUTPUT============"
echo "IP Address : $abuseIPAddr"
echo "Whitelisted: $abuseisWhite"
echo "Abuse Confidence Score: $abuseConfScore"
echo "Country Name: $abuseCountryName"
echo "Usage Type: $abuseUsageType"
echo "ISP: $abuseISP"
echo "Domain: $abuseDomain"
echo "Total Reports: $abuseTotalReports"
echo "Last Reported At: $abuseLastReportedAt"
echo "================================="