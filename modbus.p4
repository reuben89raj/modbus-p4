/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<32> INTERVAL = 0xDBBA0; // 0.9 seconds in microseconds
const bit<32> PACKETSININTERVAL = 1;
const bit<32> RESPONSETIME = 0x2DC6C0; // 3 seconds in microseconds

register<bit<32>>(65535) intervalStart;
register<bit<32>>(65535) intervalCount;

typedef bit<48>  EthernetAddress;


header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header Tcp_option_end_h {
    bit<8> kind;
}
header Tcp_option_nop_h {
    bit<8> kind;
}
header Tcp_option_ss_h {
    bit<8>  kind;
    bit<32> maxSegmentSize;
}
header Tcp_option_s_h {
    bit<8>  kind;
    bit<24> scale;
}
header Tcp_option_sack_h {
    bit<8>         kind;
    bit<8>         length;
    varbit<256>    sack;
}

header Tcp_option_ts_h {
    bit<8>  kind;
    bit<8>  length;
    bit<32> TSval;
    bit<32> TSecr;
}

header_union Tcp_option_h {
    Tcp_option_end_h  end;
    Tcp_option_nop_h  nop;
    Tcp_option_ss_h   ss;
    Tcp_option_s_h    s;
    Tcp_option_sack_h sack;
    Tcp_option_ts_h ts;
}

// Defines a stack of 10 tcp options
typedef Tcp_option_h[10] Tcp_option_stack;

header Tcp_option_padding_h {
    varbit<256> padding;
}

header modbus_t {
    bit<16> tx_id;
    bit<16> proto_id;
    bit<16> len;
    bit<8>  unit_id;
    bit<1>  fcBit;
    bit<7>  functionCode;
}

struct headers {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    tcp_t            tcp;
    Tcp_option_stack tcp_options_vec;
    Tcp_option_padding_h tcp_options_padding;
    modbus_t modbus;
}

struct fwd_metadata_t {
    bit<16> hash1;
    bit<32> l2ptr;
    bit<24> out_bd;
}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadSackOptionLength,
    TcpBadTSOptionLength
}

struct Tcp_option_sack_top
{
    bit<8> kind;
    bit<8> length;
}

struct Tcp_option_ts
{
    bit<8> kind;
    bit<8> length;
//    bit<32> TSval;
//    bit<32> TSecr;
}
// This sub-parser is intended to be apply'd just after the base
// 20-byte TCP header has been extracted.  It should be called with
// the value of the Data Offset field.  It will fill in the @vec
// argument with a stack of TCP options found, perhaps empty.

// Unless some error is detect earlier (causing this sub-parser to
// transition to the reject state), it will advance exactly to the end
// of the TCP header, leaving the packet 'pointer' at the first byte
// of the TCP payload (if any).  If the packet ends before the full
// TCP header can be consumed, this sub-parser will set
// error.PacketTooShort and transition to reject.

parser Tcp_option_parser(packet_in b,
                         in bit<4> tcp_hdr_data_offset,
                         out Tcp_option_stack vec,
                         out Tcp_option_padding_h padding
                         )
{
    bit<7> tcp_hdr_bytes_left;

    state start {
        // RFC 793 - the Data Offset field is the length of the TCP
        // header in units of 32-bit words.  It must be at least 5 for
        // the minimum length TCP header, and since it is 4 bits in
        // size, can be at most 15, for a maximum TCP header length of
        // 15*4 = 60 bytes.
        verify(tcp_hdr_data_offset >= 5, error.TcpDataOffsetTooSmall);
        tcp_hdr_bytes_left = 4 * (bit<7>) (tcp_hdr_data_offset - 5);
        // always true here: 0 <= tcp_hdr_bytes_left <= 40
        transition next_option;
    }
    state next_option {
        transition select(tcp_hdr_bytes_left) {
            0 : accept;  // no TCP header bytes left
            default : next_option_part2;
        }
    }
    state next_option_part2 {
        // precondition: tcp_hdr_bytes_left >= 1
        transition select(b.lookahead<bit<8>>()) {
            0: parse_tcp_option_end;
            1: parse_tcp_option_nop;
            2: parse_tcp_option_ss;
            3: parse_tcp_option_s;
            5: parse_tcp_option_sack;
            8: parse_tcp_option_ts;
        }
    }
    state parse_tcp_option_end {
        b.extract(vec.next.end);
        // TBD: This code is an example demonstrating why it would be
        // useful to have sizeof(vec.next.end) instead of having to
        // put in a hard-coded length for each TCP option.
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        transition consume_remaining_tcp_hdr_and_accept;
    }
    state consume_remaining_tcp_hdr_and_accept {
        // A more picky sub-parser implementation would verify that
        // all of the remaining bytes are 0, as specified in RFC 793,
        // setting an error and rejecting if not.  This one skips past
        // the rest of the TCP header without checking this.

        // tcp_hdr_bytes_left might be as large as 40, so multiplying
        // it by 8 it may be up to 320, which requires 9 bits to avoid
        // losing any information.
        b.extract(padding, (bit<32>) (8 * (bit<9>) tcp_hdr_bytes_left));
        transition accept;
    }
    state parse_tcp_option_nop {
        b.extract(vec.next.nop);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        transition next_option;
    }
    state parse_tcp_option_ss {
        verify(tcp_hdr_bytes_left >= 5, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 5;
        b.extract(vec.next.ss);
        transition next_option;
    }
    state parse_tcp_option_s {
        verify(tcp_hdr_bytes_left >= 4, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 4;
        b.extract(vec.next.s);
        transition next_option;
    }
    state parse_tcp_option_sack {
        bit<8> n_sack_bytes = b.lookahead<Tcp_option_sack_top>().length;
        // I do not have global knowledge of all TCP SACK
        // implementations, but from reading the RFC, it appears that
        // the only SACK option lengths that are legal are 2+8*n for
        // n=1, 2, 3, or 4, so set an error if anything else is seen.
        verify(n_sack_bytes == 10 || n_sack_bytes == 18 ||
               n_sack_bytes == 26 || n_sack_bytes == 34,
               error.TcpBadSackOptionLength);
        verify(tcp_hdr_bytes_left >= (bit<7>) n_sack_bytes,
               error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - (bit<7>) n_sack_bytes;
        b.extract(vec.next.sack, (bit<32>) (8 * n_sack_bytes - 16));
        transition next_option;
    }
    state parse_tcp_option_ts {
        verify(tcp_hdr_bytes_left >= 10, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 10;
        b.extract(vec.next.ts);
        transition next_option;
    }
}

parser ParserImpl(packet_in packet,
                  out headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata)
{
    const bit<16> ETHERTYPE_IPV4 = 0x0800;
    bit <1> MB_FLAG = 0;


    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        Tcp_option_parser.apply(packet, hdr.tcp.dataOffset,
                                hdr.tcp_options_vec, hdr.tcp_options_padding);

        // Check for data packet. Data packet is any packet with lenth > IPHeader-Length + TCP-Header-Length and
        // does not have ONLY the ACK flag set in TCP header. ONLY ACK translates to hdr.tcp.ctrl = 0b010000
        if ((hdr.ipv4.totalLen > (bit<16>)hdr.ipv4.ihl + (bit<16>)hdr.tcp.dataOffset) && hdr.tcp.ctrl != 0b010000) {
            MB_FLAG = 1;
        }
        transition select  (MB_FLAG) {
            1 : parse_modbus;
            default: accept;
        }
    }
    state parse_modbus {
        packet.extract(hdr.modbus);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    bit<1> direction;
    bit<16> flow_id;
    bit<16> tx_fc_id;
    bit<32> fClass_id;
    bit<16> mbapLen;
    bit<32> packet_length;

    bit<32> req_interval = PACKETSININTERVAL;
    bit<32> resp_threshold = RESPONSETIME;
  //  register<bit<32>>(65535) funcClass;
    register<bit<32>>(65535) txFcStatus;


    action drop() {
        mark_to_drop(standard_metadata);
    }

    action compute_flow_id() {
        hash (
            flow_id,
            HashAlgorithm.crc16,
            (bit<1>)0,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort
            },
            (bit<16>)65535
            );
    }

    // for checking rate of arrival -
    action compute_funcClass_Id() {
        hash (
            fClass_id,
            HashAlgorithm.crc16,
            (bit<1>)0,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.modbus.functionCode
            },
            (bit<32>)65535
            );
       // flowStatus.write((bit<32>)flow_id, 1);
    }

    // for checking response time
    action compute_tx_fc_id() {
        hash (
            tx_fc_id,
            HashAlgorithm.crc16,
            (bit<1>)0,
            {
                hdr.modbus.tx_id,
                hdr.modbus.functionCode
            },
            (bit<16>)65535
            );
        //txFcStatus.write((bit<32>)tx_fc_id, 1);
    }

    action ipv4_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action set_direction(bit<1> dir) {
        direction = dir;
    }

    table check_ports {
        key = {
            standard_metadata.ingress_port: exact;
            standard_metadata.egress_spec: exact;
        }
        actions = {
            set_direction;
            NoAction;
        }
        size = 16;
        default_action = NoAction;
    }

    action setPort() {
        standard_metadata.egress_spec = standard_metadata.egress_spec;
    }

    table flowOut {
         key = { hdr.ipv4.dstAddr: exact;
                 hdr.ipv4.srcAddr: exact;
                 hdr.ipv4.protocol: exact;
		         hdr.tcp.dstPort: exact;
		         direction: exact;
                }
         actions = {
		setPort;
		NoAction;
         }
         size = 1024;
         default_action = NoAction;
     }

     table flowIn {
         key = { hdr.ipv4.dstAddr: exact;
                 hdr.ipv4.srcAddr: exact;
                 hdr.ipv4.protocol: exact;
		         hdr.tcp.srcPort: exact;
		         direction: exact;
                }
         actions = {
		setPort;
		drop;
		NoAction;
         }
         size = 1024;
         default_action = drop;
     }

    table modbusCheck {
         key = { hdr.modbus.functionCode: exact;
                }
         actions = {
		setPort;
		drop;
		NoAction;
         }
         size = 1024;
         default_action = drop;
     }


     apply {
         if (hdr.ipv4.isValid()) {
         ipv4_lpm.apply();
         check_ports.apply();

           // valid flow check
          if(!(flowOut.apply().hit || flowIn.apply().hit )) {
                drop();
          }
          else {
            if (hdr.tcp.isValid()) {

                // Check if only TCP ;
                if(hdr.ipv4.totalLen <= ((bit<16>)(4*hdr.ipv4.ihl) + (bit<16>)(4*hdr.tcp.dataOffset))){
                        setPort();
                    } else if(hdr.modbus.isValid() && (hdr.tcp.srcPort == 502 || hdr.tcp.dstPort == 502)) { // Check if Modbus packet
                        // mbapLen = (bit<16>)hdr.ipv4.totalLen - ((bit<16>)(4*hdr.ipv4.ihl) + (bit<16>)(4*hdr.tcp.dataOffset) + 6);
                        bit<16> totalLenValue = (bit<16>)hdr.ipv4.totalLen;
                        bit<16> ihlValue = 4 * (bit<16>)hdr.ipv4.ihl;
                        bit<16> dataOffsetValue = 4 * (bit<16>)hdr.tcp.dataOffset;
                        packet_length = standard_metadata.packet_length;

                        mbapLen = (bit<16>)packet_length - (ihlValue + dataOffsetValue + 20);

                        log_msg("ipv4-totalLen: {}, ihlValue: {}, dataOffsetValue:{}, mbapLen: {},packet-Length: {}", {totalLenValue, ihlValue, dataOffsetValue, mbapLen, packet_length});

                        // Length check
                        if (mbapLen == hdr.modbus.len) {
                            if(!modbusCheck.apply().hit) {
                                drop();
			    }
			    // Check if msg is Modbus Request. If so, check arrival rate
                            if(hdr.tcp.dstPort == 502) {
                                    compute_funcClass_Id();

                                    bit<32> arrivalTime = (bit<32>)standard_metadata.ingress_global_timestamp;
                                    bit<32> intervalStartVal;
                                    intervalStart.read(intervalStartVal, (bit<32>)fClass_id);

                                    // also store the timestamp in ReqTimeStamp register for response time check
                                    compute_tx_fc_id();
                                    txFcStatus.write((bit<32>)tx_fc_id, arrivalTime);

                                    if (arrivalTime - intervalStartVal > INTERVAL) {
                                        intervalStart.write((bit<32>)fClass_id, arrivalTime);
                                        intervalCount.write(fClass_id, 1);
                                    } else {
                                        intervalStart.write((bit<32>)fClass_id, arrivalTime);
                                        bit<32> intervalCountVal;
                                        intervalCount.read(intervalCountVal, (bit<32>)fClass_id);
                                        intervalCount.write((bit<32>)fClass_id, intervalCountVal + 1);
                                        if (intervalCountVal + 1 > PACKETSININTERVAL) {
                                            drop();
                                        }
                                    }
                                } else if(hdr.tcp.srcPort == 502) {
                                    // Add check for Modbus Response
                                    compute_tx_fc_id();
                                    bit<32> current_timestamp = (bit<32>)standard_metadata.ingress_global_timestamp;
                                    bit<32> req_timestamp;
                                    txFcStatus.read(req_timestamp, (bit<32>)tx_fc_id);

                                    log_msg("current_timestamp: {}, req_timestamp: {}, resp_threshold:{}", {current_timestamp, req_timestamp, resp_threshold});
                                    if((current_timestamp - req_timestamp) > resp_threshold){
                                        drop();
                                    } else {
                                        setPort();
                                    }
                                }
                            } else {
                                // Invalid length, so drop
                                log_msg("Dropping due to invalid length");
				                drop();

                            }
                        }
                    }

            else {
                drop();
            }
        }
        }
     }
}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
        }

    }

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_options_vec);
        packet.emit(hdr.tcp_options_padding);
        packet.emit(hdr.modbus);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
ParserImpl(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
DeparserImpl()
) main;
