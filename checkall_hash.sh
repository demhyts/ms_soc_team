#!/bin/bash

#set -e
read -p "Input Hash : " inputHash
read -p "Input VT Api Key : " apiKey
curl -s -X GET https://www.virustotal.com/api/v3/search?query=$inputHash -H 'Content-Type: application/json' -H "x-apikey: $apiKey" | jq . > $inputHash-VT.json

#VT Output Variables
fileName="$inputHash-VT.json"
hashID=$(jq -r '.data[]["id"]' $VTfileName)
createDate=$(jq -r '.data[]["attributes"]["creation_date"]' $VTfileName | sed 's/^/\@/' | xargs date -d)
lastChkDate=$(jq -r '.data[]["attributes"]["last_analysis_date"]' $VTfileName | sed 's/^/\@/' | xargs date -d)
descr=$(jq -r '.data[]["attributes"]["magic"]' $VTfileName)
names=$( jq -r '.data[]["attributes"]["names"][]' $VTfileName)
crowdYaraRuleID=$(jq -r '.data[]["attributes"]["crowdsourced_yara_results"][]["ruleset_id"]' $VTfileName)
crowdYaraRuleName=$(jq -r '.data[]["attributes"]["crowdsourced_yara_results"][]["rule_name"]' $VTfileName)
crowdYaraRuleDesc=$(jq -r '.data[]["attributes"]["crowdsourced_yara_results"][]["description"]' $VTfileName)
crowdYaraRulematchDate=$(jq -r '.data[]["attributes"]["crowdsourced_yara_results"][]["match_date"]' $VTfileName | sed 's/^/\@/' | xargs date -d)
crowdYaraSource=$(jq -r '.data[]["attributes"]["crowdsourced_yara_results"][]["source"]' $VTfileName)
#sandboxVerdictZenboxCat=$(jq -r '.data[]["attributes"]["sandbox_verdicts"]["Zenbox"]["category"]' $VTfileName)
lastAnalysisStatsMal=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["malicious"]' $VTfileName)
lastAnalysisStatsSus=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["suspicious"]' $VTfileName)
lastAnalysisStatsUnd=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["undetected"]' $VTfileName)
lastAnalysisStatsHar=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["harmless"]' $VTfileName)
lastAnalysisStatsTim=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["timeout"]' $VTfileName)
lastAnalysisStatsCon=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["confirmed-timeout"]' $VTfileName)
lastAnalysisStatsFai=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["failure"]' $VTfileName)
lastAnalysisStatsTypUns=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["type-unsupported"]' $VTfileName)
popThreatCat=$(jq -r '.data[]["attributes"]["popular_threat_classification"]["popular_threat_category"][]["value"]' $VTfileName)

#Print the results
echo "=========VIRUS TOTAL============="
echo "=====VIRUS TOTAL HASH OUTPUT====="
echo "Hashing : $hashID"
echo "Create Date : $createDate"
echo "Last Analysis Date : $lastChkDate"
echo "Description : $descr"
echo "Popular Threat Category : $popThreatCat"
#echo "File Names : $names"
echo "================================="
echo "===CROWDSOURCED YARA RESULTS====="
echo "================================="
echo "Ruleset ID : $crowdYaraRuleID"
echo "Rule Name : $crowdYaraRuleName"
echo "Description : $crowdYaraRuleDesc"
echo "Match Date : $crowdYaraRulematchDate"
echo "Source : $crowdYaraSource"
echo "================================="
echo "=====LAST ANALYSIS STATS========="
echo "================================="
echo "Malicious : $lastAnalysisStatsMal"
echo "Suspicious : $lastAnalysisStatsSus"
echo "Undetected : $lastAnalysisStatsUnd"
echo "Harmless : $lastAnalysisStatsHar"
echo "Timeout : $lastAnalysisStatsTim"
echo "Confirmed-Timeout : $lastAnalysisStatsCon"
echo "Failure : $lastAnalysisStatsFai"
echo "Type Unsupported : $lastAnalysisStatsTypUns"
echo "=================================="
echo "===END OF VIRUS TOTAL OUTPUT====="
echo "=================================="
