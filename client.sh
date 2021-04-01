read -r -p "Enter location of the certificate file: " crt_file
echo -n "What's your domain used in $crt_file (e.g., demo.rust-https.org): "
read domain

curl --cacert $crt_file "https://$domain:7878"

# You will get the following error:
# ---------------------------------
# curl: (60) SSL: certificate subject name 'XXX' does not match target host name '$domain'
# More details here: https://curl.haxx.se/docs/sslcerts.html
# ---------------------------------
# if the server issuing the domain.crt ("Common Name" set in server.sh)
# is different from the target link ('$domain') above
#
# To fix this, please make sure the "Common Name" set in server.sh
# matches the <url> for curl
