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
	"strconv"
)

const netflowMinPacketSize int = 24
const netflowVersion uint16 = 5

const metricsNamespace string = "netflow"

var recordCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: metricsNamespace,
	Name:      "processed_records",
	Help:      "Number of records processed",
})

var flowGauge = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: metricsNamespace,
	Name:      "seen_flows",
	Help:      "Number of flows seen",
})

var protocolPacketCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: metricsNamespace,
	Name:      "protocol_packets",
	Help:      "Number of packets per protocol",
}, []string{"protocol", "inInterface", "inPort", "outInterface", "outPort"})

var protocolByteCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: metricsNamespace,
	Name:      "protocol_bytes",
	Help:      "Number of bytes per protocol",
}, []string{"protocol", "inInterface", "inPort", "outInterface", "outPort"})

// https://www.plixer.com/support/netflow-v5/
type Flow struct {
	version     uint16
	recordCount uint16
	uptime      uint32
	unixSeconds uint32
	unixNanos   uint32
	flowCount   uint32
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
	_ = binary.Read(buf, binary.BigEndian, &flow.flowCount)
	_ = binary.Read(buf, binary.BigEndian, &flow.engineType)
	_ = binary.Read(buf, binary.BigEndian, &flow.engineID)
	_ = binary.Read(buf, binary.BigEndian, &flow.sampling)
	return flow
}

type Record struct {
	sourceIP    net.IP
	destIP      net.IP
	nextHop     uint32
	snmpInput   uint16
	snmpOutput  uint16
	packetCount uint32
	byteCount   uint32
	uptimeFirst uint32
	uptimeLast  uint32
	sourcePort  uint16
	destPort    uint16
	pad1        uint8
	tcpFlags    uint8
	ipProtocol  uint8
	ipTOS       uint8
	sourceAS    uint16
	destAS      uint16
	sourceMask  uint8
	destMask    uint8
	pad2        uint16
}

func makeIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func readRecord(buf *bytes.Buffer) (record Record) {
	var address uint32
	_ = binary.Read(buf, binary.BigEndian, &address)
	record.sourceIP = makeIP(address)
	_ = binary.Read(buf, binary.BigEndian, &address)
	record.destIP = makeIP(address)
	_ = binary.Read(buf, binary.BigEndian, &record.nextHop)
	_ = binary.Read(buf, binary.BigEndian, &record.snmpInput)
	_ = binary.Read(buf, binary.BigEndian, &record.snmpOutput)
	_ = binary.Read(buf, binary.BigEndian, &record.packetCount)
	_ = binary.Read(buf, binary.BigEndian, &record.byteCount)
	_ = binary.Read(buf, binary.BigEndian, &record.uptimeFirst)
	_ = binary.Read(buf, binary.BigEndian, &record.uptimeLast)
	_ = binary.Read(buf, binary.BigEndian, &record.sourcePort)
	_ = binary.Read(buf, binary.BigEndian, &record.destPort)
	_ = binary.Read(buf, binary.BigEndian, &record.pad1)
	_ = binary.Read(buf, binary.BigEndian, &record.tcpFlags)
	_ = binary.Read(buf, binary.BigEndian, &record.ipProtocol)
	_ = binary.Read(buf, binary.BigEndian, &record.ipTOS)
	_ = binary.Read(buf, binary.BigEndian, &record.sourceAS)
	_ = binary.Read(buf, binary.BigEndian, &record.destAS)
	_ = binary.Read(buf, binary.BigEndian, &record.sourceMask)
	_ = binary.Read(buf, binary.BigEndian, &record.destMask)
	_ = binary.Read(buf, binary.BigEndian, &record.pad2)
	return record
}

// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
const (
	ICMP = 1
	IGMP = 2
	IPIP = 4
	TCP  = 6
	UDP  = 17
	ESP  = 50
)

func protocolToString(p uint8) string {
	switch p {
	case ICMP:
		return "ICMP"
	case IGMP:
		return "IGMP"
	case IPIP:
		return "IPIP"
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	case ESP:
		return "ESP"
	default:
		return strconv.Itoa(int(p))
	}
}

func listen(address string, debug bool) {
	connection, err := net.ListenPacket("udp4", address)
	if err != nil {
		log.Fatal(err)
	}
	buffer := make([]byte, 64*1024) // Max UDP packet size
	for {
		n, _, err := connection.ReadFrom(buffer)
		if err != nil {
			log.Fatal(err)
		}

		if n < netflowMinPacketSize {
			log.Fatal("Invalid packet")
		}
		buf := bytes.NewBuffer(buffer)
		flow := readFlow(buf)
		if flow.version != netflowVersion {
			log.Fatal("Invalid version")
		}
		if flow.recordCount == 0 {
			log.Fatal("Invalid count")
		}

		flowGauge.Set(float64(flow.flowCount))
		recordCounter.Add(float64(flow.recordCount))
		for i := 0; i < int(flow.recordCount); i++ {
			record := readRecord(buf)
			protocol := protocolToString(record.ipProtocol)
			inInterface := strconv.Itoa(int(record.snmpInput))
			outInterface := strconv.Itoa(int(record.snmpOutput))
			inPort := strconv.Itoa(int(record.sourcePort))
			outPort := strconv.Itoa(int(record.destPort))
			protocolPacketCounter.WithLabelValues(protocol, inInterface, inPort, outInterface, outPort).Add(float64(record.packetCount))
			protocolByteCounter.WithLabelValues(protocol, inInterface, inPort, outInterface, outPort).Add(float64(record.byteCount))
			if debug {
				log.Printf("[%s / %d] %s:%d (%d) -> %s:%d (%d)", protocol, record.ipTOS, record.sourceIP.String(), record.sourcePort, record.snmpInput, record.destIP.String(), record.destPort, record.snmpOutput)
			}
		}
	}
}

func main() {
	netflowAddress := flag.String("netflow-address", ":2055", "Address to listen on for Netflow UDP packets")
	metricsAddress := flag.String("metrics-address", ":8888", "Address to listen on for Prometheus metrics")
	debug := flag.Bool("debug", false, "Print debug information")
	flag.Parse()

	go listen(*netflowAddress, *debug)

	prometheus.MustRegister(recordCounter, flowGauge, protocolPacketCounter, protocolByteCounter)
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
