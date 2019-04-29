package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
)

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

func listen(abort chan error) {
	connection, err := net.ListenPacket("udp4", ":8888") // 2055
	if err != nil {
		abort <- err
	}
	buffer := make([]byte, 64*1024) // Max UDP packet size
	for {
		n, remoteAddr, err := connection.ReadFrom(buffer)
		if err != nil {
			abort <- err
		}

		if n < 24 {
			abort <- errors.New("Invalid packet")
		}
		buf := bytes.NewBuffer(buffer)
		flow := readFlow(buf)
		if flow.version != 5 {
			abort <- errors.New("Invalid version")
		}
		if flow.recordCount < 1 || flow.recordCount > 30 {
			abort <- errors.New("Invalid count")
		}
		log.Println("FROM", remoteAddr, "-", n, "-", flow.version, flow.recordCount, flow.uptime, flow.unixSeconds, flow.unixNanos, flow.sequence, flow.engineType, flow.engineID)
		for i := 0; i < int(flow.recordCount); i++ {
			record := readRecord(buf)
			log.Println("  ", ipToString(makeIP(record.sourceAddress)), "->", ipToString(makeIP(record.destAddress)), "=", record.packetCount, record.byteCount)
		}
	}
}

func main() {
	log.Print("Running...")

	abort := make(chan error)
	go listen(abort)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case err := <-abort:
			log.Fatal(err)
		case <-stop:
			log.Print("Shutting down")
			os.Exit(0)
		}
	}
}
