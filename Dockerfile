FROM        quay.io/prometheus/busybox:latest
MAINTAINER  The Prometheus Authors <prometheus-developers@googlegroups.com>

COPY snmp-exporter  /bin/snmp-exporter
COPY snmp.yml       /etc/snmp-exporter/snmp.yml

EXPOSE      9106
ENTRYPOINT  [ "/bin/snmp-exporter" ]
CMD         [ "--config.file=/etc/snmp-exporter/snmp.yml" ]
