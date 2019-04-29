FROM golang:latest

ADD . /go/src/github.com/swisspol/netflow-prometheus-exporter
RUN export GO111MODULE=on && cd /go/src/github.com/swisspol/netflow-prometheus-exporter && go install

FROM ubuntu:latest

COPY --from=0 /go/bin/netflow-prometheus-exporter /bin/netflow-prometheus-exporter
ENTRYPOINT ["/bin/netflow-prometheus-exporter"]
