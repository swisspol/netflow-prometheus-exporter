FROM golang:latest

ADD . /go/src/github.com/swisspol/netflow-prometheus-exporter
RUN cd /go/src/github.com/swisspol/netflow-prometheus-exporter && go build

FROM ubuntu:latest

COPY --from=0 /go/src/github.com/swisspol/netflow-prometheus-exporter/netflow-prometheus-exporter /bin/netflow-prometheus-exporter
ENTRYPOINT ["/bin/netflow-prometheus-exporter"]
