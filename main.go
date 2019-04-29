package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
)

const metricsNamespace string = "netflow"

var recordCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: metricsNamespace,
	Name:      "record_count",
	Help:      "Number of records collected",
})

// https://www.plixer.com/support/netflow-v5/
type Flow struct {
	version     uint16
	recordCount uint16
	uptime      uint32
	unixSeconds uint32
	unixNanos   uint32
	sequence    uint32
	engineType  uint8
	engineID    uint8
	sampling    uint16
}

func readFlow(buf *bytes.Buffer) (flow Flow) {
	_ = binary.Read(buf, binary.BigEndian, &flow.version)
	_ = binary.Read(buf, binary.BigEndian, &flow.recordCount)
	_ = binary.Read(buf, binary.BigEndian, &flow.uptime)
	_ = binary.Read(buf, binary.BigEndian, &flow.unixSeconds)
	_ = binary.Read(buf, binary.BigEndian, &flow.unixNanos)
	_ = binary.Read(buf, binary.BigEndian, &flow.sequence)
	_ = binary.Read(buf, binary.BigEndian, &flow.engineType)
	_ = binary.Read(buf, binary.BigEndian, &flow.engineID)
	_ = binary.Read(buf, binary.BigEndian, &flow.sampling)
	return flow
}

type Record struct {
	sourceAddress uint32
	destAddress   uint32
	nextHop       uint32
	snmpInput     uint16
	snmpOutput    uint16
	packetCount   uint32
	byteCount     uint32
	// TODO
}

func readRecord(buf *bytes.Buffer) (record Record) {
	_ = binary.Read(buf, binary.BigEndian, &record.sourceAddress)
	_ = binary.Read(buf, binary.BigEndian, &record.destAddress)
	_ = binary.Read(buf, binary.BigEndian, &record.nextHop)
	_ = binary.Read(buf, binary.BigEndian, &record.snmpInput)
	_ = binary.Read(buf, binary.BigEndian, &record.snmpOutput)
	_ = binary.Read(buf, binary.BigEndian, &record.packetCount)
	_ = binary.Read(buf, binary.BigEndian, &record.byteCount)
	return record
}

func makeIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func ipToString(ip net.IP) string {
	s := ip.String()
	n, err := net.LookupAddr(s)
	if err != nil {
		return s
	}
	return n[0]
}

func listen(address string) {
	connection, err := net.ListenPacket("udp4", address)
	if err != nil {
		log.Fatal(err)
	}
	buffer := make([]byte, 64*1024) // Max UDP packet size
	for {
		n, remoteAddr, err := connection.ReadFrom(buffer)
		if err != nil {
			log.Fatal(err)
		}

		if n < 24 {
			log.Fatal("Invalid packet")
		}
		buf := bytes.NewBuffer(buffer)
		flow := readFlow(buf)
		if flow.version != 5 {
			log.Fatal("Invalid version")
		}
		if flow.recordCount < 1 || flow.recordCount > 30 {
			log.Fatal("Invalid count")
		}
		log.Println("FROM", remoteAddr, "-", n, "-", flow.version, flow.recordCount, flow.uptime, flow.unixSeconds, flow.unixNanos, flow.sequence, flow.engineType, flow.engineID)
		for i := 0; i < int(flow.recordCount); i++ {
			record := readRecord(buf)
			log.Print("  ", ipToString(makeIP(record.sourceAddress)), "->", ipToString(makeIP(record.destAddress)), "=", record.packetCount, record.byteCount)
		}
		recordCounter.Add(float64(flow.recordCount))
	}
}

func main() {
	netflowAddress := flag.String("netflow-address", ":2055", "Address to listen on for Netflow UDP packets")
	metricsAddress := flag.String("metrics-address", ":8888", "Address to listen on for Prometheus metrics")
	flag.Parse()

	go listen(*netflowAddress)

	prometheus.MustRegister(recordCounter)
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Fatal(http.ListenAndServe(*metricsAddress, nil))
	}()

	log.Printf("Running NetFlow collector on '%s' and exposing metrics on '%s'...", *netflowAddress, *metricsAddress)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-stop:
			log.Print("Shutting down")
			os.Exit(0)
		}
	}
}
