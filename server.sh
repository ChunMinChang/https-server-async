# Generate a SSL Certificate if needed
need_new_cert=true
read -r -p "Do you have a SSL certificate with its private key, and you remember its subject name? [y/N] " response
case "$response" in
[yY][eE][sS] | [yY])
  need_new_cert=false
  ;;
*) ;;
esac

if $need_new_cert; then
  printf "Generating a SSL Certificate ...\n"
  printf "Enter your host name (e.g., demo.rust-https.org): "
  read domain

  # Create a Self-Signed Certificate via OpenSSL
  # See https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs#generate-a-self-signed-certificate
  RED='\033[0;31m'
  NC='\033[0m' # No Color
  printf "**************************************************************\n"
  printf "Please enter '${RED}${domain}${NC}' in '${RED}Common Name${NC}' when creating the certificate.\n"
  printf "Example:\n\n"
  printf "Country Name (2 letter code) [AU]:US\n"
  printf "State or Province Name (full name) [Some-State]:Oregon\n"
  printf "Locality Name (eg, city) []:Portland\n"
  printf "Organization Name (eg, company) [Internet Widgits Pty Ltd]: Solar System\n"
  printf "Organizational Unit Name (eg, section) []: Earth\n"
  printf "Common Name (e.g. server FQDN or YOUR name) []:${RED}${domain}${NC}\n"
  printf "Email Address []:earth@solar.universe\n"
  printf "**************************************************************"

  key_file=domain.key
  crt_file=domain.crt
  openssl req \
    -newkey rsa:2048 -nodes -keyout $key_file \
    -x509 -days 7 -out $crt_file
  printf "Certificate: '${RED}${crt_file}${NC}' and its private key: '${RED}${key_file}${NC}' are created! They are valid for 7 days\n"

  # Add $domain to /etc/hosts
  newhost="127.0.0.1 $domain"
  if !(grep -q "$newhost" "/etc/hosts"); then
    printf "Append $newhost in /etc/hosts\n"
    echo $newhost | sudo tee -a /etc/hosts
  fi
  printf "**************************************************************\n"
  printf "Please delete '${RED}${newhost}${NC}' in '${RED}/etc/hosts${NC}' after closing the server\n"
  printf "**************************************************************\n"
else
  read -r -p "Enter location of the certificate file: " crt_file
  read -r -p "Enter location of the private key file: " key_file
fi

# Start running server
printf "Now start the server on 127.0.0.1:7878. Close server by Ctrl-C\n"
printf "Please open ${RED}another terminal${NC} console to run ${RED}./client.sh${NC}\n"
cargo run -- 127.0.0.1:7878 --cert $crt_file --key $key_file
