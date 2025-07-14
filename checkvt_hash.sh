#!/bin/bash

#set -e
read -p "Input Hash : " inputHash
read -p "Input VT Api Key : " apiKey
curl -s -X GET https://www.virustotal.com/api/v3/search?query=$inputHash -H 'Content-Type: application/json' -H "x-apikey: $apiKey" | jq . > $inputHash.json

fileName="$inputHash.json"
hashID=$(jq -r '.data[]["id"]' $fileName)
createDate=$(jq -r '.data[]["attributes"]["creation_date"]' $fileName | sed 's/^/\@/' | xargs date -d)
lastChkDate=$(jq -r '.data[]["attributes"]["last_analysis_date"]' $fileName | sed 's/^/\@/' | xargs date -d)
descr=$(jq -r '.data[]["attributes"]["magic"]' $fileName)
names=$( jq -r '.data[]["attributes"]["names"][]' $fileName)
crowdYaraRuleID=$(jq -r '.data[]["attributes"]["crowdsourced_yara_results"][]["ruleset_id"]' $fileName)
crowdYaraRuleName=$(jq -r '.data[]["attributes"]["crowdsourced_yara_results"][]["rule_name"]' $fileName)
crowdYaraRuleDesc=$(jq -r '.data[]["attributes"]["crowdsourced_yara_results"][]["description"]' $fileName)
crowdYaraRulematchDate=$(jq -r '.data[]["attributes"]["crowdsourced_yara_results"][]["match_date"]' $fileName | sed 's/^/\@/' | xargs date -d)
crowdYaraSource=$(jq -r '.data[]["attributes"]["crowdsourced_yara_results"][]["source"]' $fileName)
#sandboxVerdictZenboxCat=$(jq -r '.data[]["attributes"]["sandbox_verdicts"]["Zenbox"]["category"]' $fileName)
lastAnalysisStatsMal=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["malicious"]' $fileName)
lastAnalysisStatsSus=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["suspicious"]' $fileName)
lastAnalysisStatsUnd=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["undetected"]' $fileName)
lastAnalysisStatsHar=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["harmless"]' $fileName)
lastAnalysisStatsTim=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["timeout"]' $fileName)
lastAnalysisStatsCon=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["confirmed-timeout"]' $fileName)
lastAnalysisStatsFai=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["failure"]' $fileName)
lastAnalysisStatsTypUns=$(jq -r '.data[]["attributes"]["last_analysis_stats"]["type-unsupported"]' $fileName)
popThreatCat=$(jq -r '.data[]["attributes"]["popular_threat_classification"]["popular_threat_category"]["value"]' $fileName)

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