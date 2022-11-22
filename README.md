# ctf-password-reset

docker build -t ctf-reset-password .  

docker run -e SERVER_ADDRESS='0.0.0.0:80' \
    -e SECRET_KEY='...' \
    -e ADMIN_EMAIL='...' \
    -e ADMIN_PASSWORD='...' \
    -e SMTP_HOST='...' \
    -e SMTP_LOGIN='...' \
    -e SMTP_PASSWORD='...' \
    -e FROM_EMAIL='...' \
    -e FLAG='...' \
    -p 80:80 ctf-reset-password
