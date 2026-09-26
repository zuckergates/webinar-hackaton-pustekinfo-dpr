FROM postgres:17-bookworm@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652
COPY start.sh /usr/local/bin/lab-start.sh
RUN chmod +x /usr/local/bin/lab-start.sh
ENTRYPOINT ["bash", "/usr/local/bin/lab-start.sh"]
CMD ["postgres", "-c", "ssl=on", "-c", "ssl_cert_file=/var/lib/postgresql/tls/server.crt", "-c", "ssl_key_file=/var/lib/postgresql/tls/server.key", "-c", "hba_file=/etc/postgresql/pg_hba.conf", "-c", "password_encryption=scram-sha-256", "-c", "log_statement=none", "-c", "log_min_error_statement=panic"]
