package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"bytes"
	"strings"

	"mtproto"

	"github.com/miekg/pcap"
	"github.com/umarudy/cpretty"
)

const (
	TYPE_IP  = 0x0800
	TYPE_ARP = 0x0806
	TYPE_IP6 = 0x86DD

	IP_ICMP = 1
	IP_INIP = 4
	IP_TCP  = 6
	IP_UDP  = 17
)

var (
	device  = flag.String("i", "", "interface")
	ofile   = flag.String("w", "", "file")
	snaplen = flag.Int("s", 65535, "snaplen")
	hexdump = flag.Bool("X", false, "hexdump")
	help    = flag.Bool("h", false, "help")
)

func main() {
	
	expr := ""

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [ -i interface ] [ -s snaplen ] [ -X hexdump ] [ -w file ] [ -h show usage] [ expression ] \n", os.Args[0])
		os.Exit(1)
	}

	flag.Parse()

	if len(flag.Args()) > 0 {
		expr = flag.Arg(0)
	}

	if *help { flag.Usage() }

	if *device == "" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, "tcpdump: couldn't find any devices:", err)
		}
		if 0 == len(devs) {
			flag.Usage()
		}
		*device = devs[0].Name
	}

	h, err := pcap.OpenLive(*device, int32(*snaplen), true, 500)
	if h == nil {
		fmt.Fprintf(os.Stderr, "tcpdump: %s", err)
		return
	}
	defer h.Close()

	if expr != "" {
		fmt.Println("tcpdump: setting filter to", expr)
		ferr := h.SetFilter(expr)
		if ferr != nil {
			fmt.Println("tcpdump:", ferr)
		}
	}

	if *ofile != "" {
		dumper, oerr := h.DumpOpen(ofile)
		addHandler(h, dumper)
		if oerr != nil {
			fmt.Fprintln(os.Stderr, "tcpdump: couldn't write to file:", oerr)
		}
		_, lerr := h.PcapLoop(0, dumper)
		if lerr != nil {
			fmt.Fprintln(os.Stderr, "tcpdump: loop error:", lerr, h.Geterror())
		}
		defer h.PcapDumpClose(dumper)
		return
	}

	for pkt, r := h.NextEx(); r >= 0; pkt, r = h.NextEx() {
		if r == 0 {
			// timeout, continue
			continue
		}
		pkt.Decode()
		str := pkt.String()
		var i int 
		i = strings.Index( str , "WIB")// khusus dipakai di depok
		if i > 0 {
			i += strings.Index( str[i+3:] , "WIB") + 3
			str = str[i+4:]
		}
		r := strings.Split( str," " )
		if r[0] == "TCP" {
		  fmt.Println( str )
		  PacketAsString( pkt )
		}

		//if *hexdump {
		//	Hexdump(pkt)
		//}
		

	}
	fmt.Fprintln(os.Stderr, "tcpdump:", h.Geterror())

}

func Unpack(skip int, p []byte) interface{} {
	
	dbuf := mtproto.NewDecodeBuf(p[skip:]) // umumnya skip(8 auth_key_id + 8 message_id + 4 message_length = 20)

	o := dbuf.Object()
	fmt.Printf("%# v\n", cpretty.Formatter(o))
	
	return o
}

func printHeader(data []byte, start int, end int, label string){
	for i := start; i <= end; i++{
		fmt.Printf( "%02x ", data[i])
	}
	println(label)
}

// Return the string representation of the provided packet.
func PacketAsString(pkt *pcap.Packet) string {
	buf := bytes.NewBufferString("")
	var data []byte
	var ll_header int
	if (pkt.Caplen > 66+20){ // menghindari crash karena bukan mtproto
		
		ll_header = 65 // low level header
	}else{
		
		return ""
	}
	data = pkt.Data[ll_header:]
	
	for i := int(1); i < len(data); i++ { /// hitungan mulai dari 1
		//fmt.Fprintf(buf, "%c", pkt.Data[i])
		fmt.Printf( "%02x ", data[i])
		if (i % 20 == 0 && i!=0 ) {
		  fmt.Println( " [", i, "]")
		}
	}

	skip_header := 2
	set_skip := 23
	fmt.Println( "\n\n")

	if len(data) > 0 {
		if (len(data) > 23){
			if (data[1] == 0xef){
				set_skip = 23
			}else{
				skip_header = 1
				set_skip = 22
			}
	
			fmt.Println()
			printHeader(data, 1+skip_header, 8+skip_header, "auth_key_id")
			printHeader(data, 9+skip_header, 16+skip_header, "message_id")
			printHeader(data, 17+skip_header, 20+skip_header, "message_length")			

			Unpack(set_skip, data)
		}
	  fmt.Println( "\n")
	}
	return string(buf.Bytes())
}

func addHandler(h *pcap.Pcap, dumper *pcap.PcapDumper) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			fmt.Fprintln(os.Stderr, "tcpdump: received signal:", sig)
			if os.Interrupt == sig {
				h.PcapDumpClose(dumper)
				h.Close()
				os.Exit(1)
			}
		}
	}()
}
/*
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func Hexdump(pkt *pcap.Packet) {
	for i := 0; i < len(pkt.Data); i += 16 {
		Dumpline(uint32(i), pkt.Data[i:min(i+16, len(pkt.Data))])
	}
}

func Dumpline(addr uint32, line []byte) {
	//fmt.Printf("\t0x%04x: ", int32(addr))
	var i uint16
	for i = 0; i < 16 && i < uint16(len(line)); i++ {
		if i%2 == 0 {
			fmt.Print(" ")
		}
		fmt.Printf("%02x", line[i])
	}
	for j := i; j <= 16; j++ {
		if j%2 == 0 {
			fmt.Print(" ")
		}
		fmt.Print("  ")
	}
	fmt.Print("  ")
	for i = 0; i < 16 && i < uint16(len(line)); i++ {
		if line[i] >= 32 && line[i] <= 126 {
			fmt.Printf("%c\n", line[i])
		} else {
			fmt.Print(".")
		}
	}
	fmt.Println()
}
*/